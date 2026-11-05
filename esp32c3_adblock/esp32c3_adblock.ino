/*
 * ESP32-C3 DNS Ad Blocker  (Arduino IDE)
 *
 * Idea borrowed from github.com/M-Abozaid/esp32-c3-adblock:
 *   keep the blocklist in FLASH as sorted 40-bit hashes (5 bytes/domain) and
 *   binary-search it, instead of holding domain strings in RAM.
 *   100k domains = ~500 KB flash, ~100 KB RAM only while updating.
 *
 * Blocklist can be loaded two ways (both included):
 *   A) The board downloads a hosts-format list itself and builds the hash file
 *      (weekly, or on demand from the web page).
 *   B) You build blocklist.bin on a PC (tools/build_blocklist.py) and upload it
 *      on the web page.
 *
 * Arduino IDE settings:
 *   Board            : ESP32C3 Dev Module
 *   USB CDC On Boot  : Enabled
 *   Partition Scheme : "Default 4MB with spiffs (1.2MB APP/1.5MB SPIFFS)"
 *   (LittleFS lives in that SPIFFS partition.)
 *
 * Web page: http://<LOCAL_IP>/   (user/pass below)
 */

#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <algorithm>

// ======================= EDIT THESE =======================
#include "secrets.h"   // WIFI_SSID, WIFI_PASS, WEB_USER, WEB_PASS  (copy secrets.example.h -> secrets.h)

IPAddress LOCAL_IP(192, 168, 1, 53);   // fixed IP of the board (outside DHCP range)
IPAddress GATEWAY(192, 168, 1, 1);     // router IP
IPAddress SUBNET(255, 255, 255, 0);
IPAddress UPSTREAM_DNS(192, 168, 1, 1);    // where allowed lookups are forwarded (router; try 8.8.8.8 or 1.1.1.1 if you prefer)


// hosts-format list the board downloads (one "0.0.0.0 domain" per line)
const char* LIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
const uint32_t UPDATE_INTERVAL_MS = 7UL * 24 * 3600 * 1000;  // weekly (uptime based)
const bool LOG_BLOCKS = false;         // print every blocked lookup to Serial (slows DNS if no PC attached)
// ==========================================================

// Never blocked (connectivity checks, so phones don't show "no internet").
const char* const ALLOWLIST[] = {
  "msftconnecttest.com", "connectivitycheck.gstatic.com", "captive.apple.com",
  "detectportal.firefox.com", "clients3.google.com"
};
// Always blocked, even before any list is loaded. Add your own here.
const char* const CUSTOM_BLOCK[] = {
  "doubleclick.net", "googlesyndication.com", "googleadservices.com",
  "adservice.google.com", "adnxs.com", "taboola.com", "outbrain.com",
  "criteo.com", "scorecardresearch.com", "pubmatic.com", "rubiconproject.com",
  "openx.net", "amazon-adsystem.com", "moatads.com", "adsrvr.org",
  "ads-twitter.com", "ads.tiktok.com", "app-measurement.com",
  "unityads.unity3d.com", "applovin.com", "mopub.com", "adcolony.com",
  // YouTube / Facebook: only the dedicated ad & tracking hostnames (the video/feed
  // ads themselves share domains with the content, so DNS can't remove those).
  "ads.youtube.com", "an.facebook.com", "pixel.facebook.com", "ads.facebook.com"
};
#define N_ALLOW  (sizeof(ALLOWLIST) / sizeof(ALLOWLIST[0]))
#define N_CUSTOM (sizeof(CUSTOM_BLOCK) / sizeof(CUSTOM_BLOCK[0]))

// ---------------- constants / globals ----------------
const char*    BL_FILE = "/bl.bin";
const char*    BL_TMP  = "/bl.tmp";
const size_t   BL_HDR  = 8;                 // "ADB1" + 4 reserved bytes
const uint16_t DNS_PORT = 53;
const uint16_t UPSTREAM_LOCAL_PORT = 5300;
const size_t   BUF_SIZE = 1232;
const int      SLOTS = 32;
const uint32_t SLOT_TIMEOUT_MS = 3000;

WiFiUDP serverUdp, upstreamUdp;
WebServer server(80);

struct Pending { bool used; IPAddress ip; uint16_t port, origId, upId; uint32_t ts; };
Pending pending[SLOTS];
int nextSlot = 0;
uint8_t buf[BUF_SIZE];

File     blf;                 // open read handle on /bl.bin
uint32_t blCount = 0;         // entries in /bl.bin
uint32_t cntTotal = 0, cntBlocked = 0;
volatile bool updating = false, updateRequested = false;
uint32_t nextUpdateMs = 0;
char statusMsg[80] = "idle";

void servicePoll(bool web);
void setStatus(const char* fmt, ...) {
  va_list ap; va_start(ap, fmt);
  vsnprintf(statusMsg, sizeof(statusMsg), fmt, ap);
  va_end(ap);
  Serial.printf("[status] %s\n", statusMsg);
}

// ---------------- hashing (must match tools/build_blocklist.py) ----------------
uint64_t hash40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;               // FNV-1a 64
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  h ^= (h >> 40);
  return h & 0xFFFFFFFFFFULL;                       // keep 40 bits
}

// ---------------- flash blocklist ----------------
void openBlocklist() {
  if (blf) blf.close();
  blCount = 0;
  if (!LittleFS.exists(BL_FILE)) return;
  blf = LittleFS.open(BL_FILE, "r");
  if (!blf) return;
  uint8_t h[BL_HDR];
  size_t sz = blf.size();
  if (sz < BL_HDR || blf.read(h, BL_HDR) != BL_HDR || memcmp(h, "ADB1", 4) != 0 || ((sz - BL_HDR) % 5)) {
    blf.close();
    return;
  }
  blCount = (sz - BL_HDR) / 5;
}

bool blLookup(uint64_t key) {
  if (!blCount) return false;
  uint32_t lo = 0, hi = blCount;
  uint8_t b[5];
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    blf.seek(BL_HDR + (size_t)mid * 5);
    if (blf.read(b, 5) != 5) return false;
    uint64_t v = ((uint64_t)b[0] << 32) | ((uint64_t)b[1] << 24) | ((uint64_t)b[2] << 16) |
                 ((uint64_t)b[3] << 8) | b[4];
    if (v == key) return true;
    if (v < key) lo = mid + 1; else hi = mid;
  }
  return false;
}

// Check header, 5-byte alignment and strictly ascending order.
bool verifyFile(const char* path, uint32_t* countOut) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  size_t sz = f.size();
  uint8_t hdr[BL_HDR];
  if (sz < BL_HDR || f.read(hdr, BL_HDR) != BL_HDR || memcmp(hdr, "ADB1", 4) != 0 || ((sz - BL_HDR) % 5)) {
    f.close(); return false;
  }
  uint32_t n = (sz - BL_HDR) / 5, done = 0;
  uint64_t prev = 0; bool first = true;
  uint8_t chunk[500];
  while (done < n) {
    uint32_t take = min<uint32_t>(100, n - done);
    if (f.read(chunk, take * 5) != take * 5) { f.close(); return false; }
    for (uint32_t i = 0; i < take; i++) {
      const uint8_t* b = chunk + i * 5;
      uint64_t v = ((uint64_t)b[0] << 32) | ((uint64_t)b[1] << 24) | ((uint64_t)b[2] << 16) |
                   ((uint64_t)b[3] << 8) | b[4];
      if (!first && v <= prev) { f.close(); return false; }
      prev = v; first = false;
    }
    done += take;
  }
  f.close();
  if (countOut) *countOut = n;
  return n > 0;
}

// Validate BL_TMP and atomically-ish swap it in as BL_FILE.
bool installTmp() {
  uint32_t n = 0;
  if (!verifyFile(BL_TMP, &n)) { LittleFS.remove(BL_TMP); return false; }
  if (blf) blf.close();
  blCount = 0;
  LittleFS.remove(BL_FILE);
  bool ok = LittleFS.rename(BL_TMP, BL_FILE);
  openBlocklist();
  return ok && blCount > 0;
}

// ---------------- blocking decision ----------------
bool inList(const char* const* list, size_t n, const char* name) {
  const char* s = name;
  while (s) {
    for (size_t i = 0; i < n; i++) if (strcmp(s, list[i]) == 0) return true;
    s = strchr(s, '.');
    if (s) s++;
  }
  return false;
}

bool inBlocklistFile(const char* name) {
  if (!blCount) return false;
  const char* s = name;
  while (s && strchr(s, '.')) {                    // never test a bare TLD
    if (blLookup(hash40(s, strlen(s)))) return true;
    s = strchr(s, '.') + 1;
  }
  return false;
}

bool isBlocked(const char* name) {
  if (inList(ALLOWLIST, N_ALLOW, name)) return false;
  if (inList(CUSTOM_BLOCK, N_CUSTOM, name)) return true;
  return inBlocklistFile(name);
}

// ---------------- DNS ----------------
int parseQuestion(const uint8_t* p, int len, char* name, size_t nameMax, uint16_t* qtype) {
  if (len < 17) return -1;
  int pos = 12; size_t o = 0;
  while (pos < len) {
    uint8_t l = p[pos++];
    if (l == 0) break;
    if (l & 0xC0) return -1;
    if (pos + l > len || o + l + 1 >= nameMax) return -1;
    if (o) name[o++] = '.';
    for (uint8_t i = 0; i < l; i++) name[o++] = tolower(p[pos++]);
  }
  name[o] = 0;
  if (pos + 4 > len) return -1;
  *qtype = (p[pos] << 8) | p[pos + 1];
  return pos + 4;
}

// Blocked reply must be: question + (optional) 1 answer, NS=AR=0 (EDNS stripped).
int buildBlockedReply(int qEnd, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80;
  buf[6] = 0; buf[7] = 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  int len = qEnd;
  if (qtype == 1 || qtype == 28) {                  // A / AAAA -> all zeros
    uint16_t rdlen = (qtype == 1) ? 4 : 16;
    buf[7] = 1;
    buf[len++] = 0xC0; buf[len++] = 0x0C;
    buf[len++] = qtype >> 8; buf[len++] = qtype & 0xFF;
    buf[len++] = 0; buf[len++] = 1;
    buf[len++] = 0; buf[len++] = 0; buf[len++] = 0; buf[len++] = 60;
    buf[len++] = rdlen >> 8; buf[len++] = rdlen & 0xFF;
    for (int i = 0; i < rdlen; i++) buf[len++] = 0;
  }
  return len;
}

void handleClientQuery(int len, IPAddress cip, uint16_t cport) {
  char name[256]; uint16_t qtype;
  int qEnd = parseQuestion(buf, len, name, sizeof(name), &qtype);
  if (qEnd < 0 || (buf[2] & 0x80)) return;
  cntTotal++;

  if (isBlocked(name)) {
    cntBlocked++;
    int rlen = buildBlockedReply(qEnd, qtype);
    serverUdp.beginPacket(cip, cport);
    serverUdp.write(buf, rlen);
    serverUdp.endPacket();
    if (LOG_BLOCKS) Serial.printf("BLOCK  %s\n", name);
    return;
  }

  int slot = nextSlot; nextSlot = (nextSlot + 1) % SLOTS;
  Pending& p = pending[slot];
  p.used = true; p.ip = cip; p.port = cport;
  p.origId = (buf[0] << 8) | buf[1];
  p.upId = (slot << 11) | (esp_random() & 0x7FF);
  p.ts = millis();
  buf[0] = p.upId >> 8; buf[1] = p.upId & 0xFF;
  upstreamUdp.beginPacket(UPSTREAM_DNS, 53);
  upstreamUdp.write(buf, len);
  upstreamUdp.endPacket();
}

void handleUpstreamReply(int len) {
  if (len < 12) return;
  uint16_t id = (buf[0] << 8) | buf[1];
  int slot = id >> 11;
  if (slot >= SLOTS) return;
  Pending& p = pending[slot];
  if (!p.used || p.upId != id) return;
  if (millis() - p.ts > SLOT_TIMEOUT_MS) { p.used = false; return; }
  buf[0] = p.origId >> 8; buf[1] = p.origId & 0xFF;
  serverUdp.beginPacket(p.ip, p.port);
  serverUdp.write(buf, len);
  serverUdp.endPacket();
  p.used = false;
}

void dnsPoll() {
  for (int k = 0; k < 4; k++) {
    int n = serverUdp.parsePacket();
    if (n <= 0) break;
    if (n > (int)BUF_SIZE) continue;
    IPAddress cip = serverUdp.remoteIP(); uint16_t cport = serverUdp.remotePort();
    n = serverUdp.read(buf, BUF_SIZE);
    if (n > 0) handleClientQuery(n, cip, cport);
  }
  for (int k = 0; k < 4; k++) {
    int m = upstreamUdp.parsePacket();
    if (m <= 0) break;
    if (m > (int)BUF_SIZE) continue;
    m = upstreamUdp.read(buf, BUF_SIZE);
    if (m > 0) handleUpstreamReply(m);
  }
}

// Keep DNS (and optionally the web page) alive during long operations.
void servicePoll(bool web) {
  dnsPoll();
  if (web) server.handleClient();
}

// ---------------- on-device list download + hashing ----------------
// Receives the downloaded text, parses hosts / plain-domain lines, and either
// counts domains (pass 0) or collects hashes that fall in one hash range.
class ListSink : public Stream {
public:
  bool collect = false;
  uint32_t total = 0;
  uint64_t* arr = nullptr;
  uint32_t cap = 0, cnt = 0, parts = 1, range = 0;
  bool overflow = false;

  void startCount() { collect = false; total = 0; resetLine(); }
  void startCollect(uint64_t* a, uint32_t c, uint32_t p, uint32_t r) {
    collect = true; arr = a; cap = c; cnt = 0; parts = p; range = r; overflow = false; resetLine();
  }
  void finish() { if (len) processLine(); resetLine(); }

  int available() override { return 0; }
  int read() override { return -1; }
  int peek() override { return -1; }
  void flush() override {}
  size_t write(uint8_t c) override { feed(c); return 1; }
  size_t write(const uint8_t* b, size_t n) override {
    for (size_t i = 0; i < n; i++) feed(b[i]);
    servicePoll(true);                               // keep DNS + web alive while downloading
    return n;
  }

private:
  char line[260]; size_t len = 0; bool skip = false;
  void resetLine() { len = 0; skip = false; }
  void feed(uint8_t c) {
    if (c == '\n') { if (len && !skip) processLine(); resetLine(); }
    else if (c == '\r') {}
    else if (len < sizeof(line) - 1) line[len++] = c;
    else skip = true;
  }
  static bool validDomain(char* d, size_t n) {
    if (n < 4 || n > 253 || !strchr(d, '.')) return false;
    if (d[0] == '.' || !isalpha((uint8_t)d[n - 1])) return false;   // TLD must be alphabetic (drops IPs)
    for (size_t i = 0; i < n; i++) {
      char c = tolower((uint8_t)d[i]); d[i] = c;
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return false;
    }
    return strcmp(d, "localhost.localdomain") != 0;
  }
  void addDomain(char* d) {
    size_t n = strlen(d);
    if (!validDomain(d, n)) return;
    uint64_t h = hash40(d, n);
    if (!collect) { total++; return; }
    if ((uint32_t)((h * parts) >> 40) != range) return;
    if (cnt < cap) arr[cnt++] = h; else overflow = true;
  }
  void processLine() {
    line[len] = 0;
    char* c = strchr(line, '#'); if (c) *c = 0;
    char* tok[8]; int nt = 0; char* p = line;
    while (*p && nt < 8) {
      while (*p == ' ' || *p == '\t') p++;
      if (!*p) break;
      tok[nt++] = p;
      while (*p && *p != ' ' && *p != '\t') p++;
      if (*p) *p++ = 0;
    }
    for (int i = (nt == 1 ? 0 : 1); i < nt; i++) addDomain(tok[i]);   // hosts: skip the IP column
  }
};

// Takes Stream& (not ListSink&) on purpose: Arduino auto-generates prototypes
// above the class definition, which breaks functions that take a sketch-defined type.
bool downloadPass(Stream& sink) {
  WiFiClientSecure client;
  client.setInsecure();      // no certificate check (see notes): list is public, but a MITM could poison it
  HTTPClient http;
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setConnectTimeout(10000);
  http.setTimeout(20000);
  if (!http.begin(client, LIST_URL)) return false;
  int code = http.GET();
  if (code != 200) {
    char tlsErr[100] = "";
    int e = client.lastError(tlsErr, sizeof(tlsErr));
    Serial.printf("[download] HTTP code %d (%s), TLS error %d: %s, free heap %u, max block %u\n",
                  code, HTTPClient::errorToString(code).c_str(), e, tlsErr,
                  ESP.getFreeHeap(), ESP.getMaxAllocHeap());
    setStatus("HTTP %d: %s", code, e ? tlsErr : HTTPClient::errorToString(code).c_str());
    http.end();
    return false;
  }
  int r = http.writeToStream(&sink);
  http.end();
  return r > 0;
}

bool updateBlocklist() {
  updating = true;
  bool ok = false;
  uint64_t* arr = nullptr;
  File out;
  do {
    uint32_t maxAlloc = ESP.getMaxAllocHeap();
    uint32_t cap = 12000;
    if (maxAlloc < 80000 + cap * 8) cap = (maxAlloc > 90000) ? (maxAlloc - 80000) / 8 : 0;
    if (cap < 2000) { setStatus("FAIL: not enough free RAM"); break; }

    // Pass 0: count domains so we know how many hash ranges are needed.
    ListSink sink;
    auto pass = [&](ListSink& s) { bool r = downloadPass(s); s.finish(); return r; };
    setStatus("download pass 0 (counting)");
    sink.startCount();
    if (!pass(sink)) { if (strncmp(statusMsg, "HTTP", 4)) setStatus("FAIL: download (count pass)"); break; }
    uint32_t n = sink.total;
    if (n < 1000) { setStatus("FAIL: list too small (%u)", n); break; }
    uint32_t parts = (uint32_t)((n * 1.15) / cap) + 1;
    if (parts > 64) { setStatus("FAIL: list too big (%u)", n); break; }
    size_t freeFs = LittleFS.totalBytes() - LittleFS.usedBytes();
    if ((uint64_t)n * 5 + BL_HDR > freeFs) { setStatus("FAIL: flash full (need %u KB)", n * 5 / 1024); break; }

    arr = (uint64_t*)malloc(cap * sizeof(uint64_t));
    if (!arr) { setStatus("FAIL: malloc"); break; }
    LittleFS.remove(BL_TMP);
    out = LittleFS.open(BL_TMP, "w");
    if (!out) { setStatus("FAIL: cannot create temp file"); break; }
    const uint8_t hdr[BL_HDR] = {'A', 'D', 'B', '1', 0, 0, 0, 0};
    out.write(hdr, BL_HDR);

    uint32_t written = 0; bool passesOk = true;
    for (uint32_t r = 0; r < parts && passesOk; r++) {
      bool done = false;
      for (int attempt = 0; attempt < 3 && !done; attempt++) {
        setStatus("pass %u/%u (try %d)", r + 1, parts, attempt + 1);
        sink.startCollect(arr, cap, parts, r);
        if (pass(sink) && !sink.overflow) done = true;
        else if (sink.overflow) break;               // retrying won't help
      }
      if (!done) { setStatus("FAIL: pass %u/%u", r + 1, parts); passesOk = false; break; }

      std::sort(arr, arr + sink.cnt);
      uint64_t prev = UINT64_MAX;
      for (uint32_t i = 0; i < sink.cnt; i++) {
        if (arr[i] == prev) continue;
        prev = arr[i];
        uint8_t rec[5] = {(uint8_t)(prev >> 32), (uint8_t)(prev >> 24), (uint8_t)(prev >> 16),
                          (uint8_t)(prev >> 8), (uint8_t)prev};
        if (out.write(rec, 5) != 5) { setStatus("FAIL: flash write"); passesOk = false; break; }
        written++;
      }
      servicePoll(true);
    }
    out.close();
    free(arr); arr = nullptr;
    if (!passesOk) break;
    if (written < 1000) { setStatus("FAIL: only %u entries", written); break; }
    if (!installTmp()) { setStatus("FAIL: verify/install"); break; }
    setStatus("OK: %u domains loaded", blCount);
    ok = true;
  } while (false);

  if (out) out.close();
  if (arr) free(arr);
  if (!ok) LittleFS.remove(BL_TMP);
  updating = false;
  return ok;
}

// ---------------- web page ----------------
const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>C3 AdBlock</title>
<style>body{font-family:system-ui;max-width:520px;margin:2em auto;padding:0 1em}
td{padding:4px 12px 4px 0}button{padding:6px 14px;margin:4px 0}#msg{margin-top:1em;color:#06c}</style></head><body>
<h2>ESP32-C3 Ad Blocker</h2>
<table>
<tr><td>Blocklist entries</td><td id=entries>-</td></tr>
<tr><td>Queries</td><td id=queries>-</td></tr>
<tr><td>Blocked</td><td id=blocked>-</td></tr>
<tr><td>Free heap</td><td id=heap>-</td></tr>
<tr><td>Uptime (s)</td><td id=uptime>-</td></tr>
<tr><td>Status</td><td id=status>-</td></tr></table>
<h3>Load blocklist</h3>
<button onclick="act('/update')">A) Download list now</button><br>
<input type=file id=f> <button onclick="up()">B) Upload blocklist.bin</button>
<div id=msg></div>
<script>
const H={'X-Requested-With':'c3-adblock'};
function show(r){return r.text().then(t=>{document.getElementById('msg').textContent=t})}
function act(u){fetch(u,{method:'POST',headers:H}).then(show)}
function up(){const f=document.getElementById('f').files[0];if(!f)return;
 const fd=new FormData();fd.append('f',f);
 document.getElementById('msg').textContent='Uploading...';
 fetch('/upload',{method:'POST',headers:H,body:fd}).then(show)}
function poll(){fetch('/stats.json').then(r=>r.json()).then(j=>{for(const k in j)document.getElementById(k).textContent=j[k]}).catch(()=>{})}
poll();setInterval(poll,4000);
</script></body></html>)HTML";

bool authOK() {
  if (!server.authenticate(WEB_USER, WEB_PASS)) { server.requestAuthentication(); return false; }
  return true;
}
bool postOK() {                       // auth + anti-CSRF header (plain <img>/<form> can't set it)
  if (!authOK()) return false;
  if (server.header("X-Requested-With") != "c3-adblock") { server.send(403, "text/plain", "forbidden"); return false; }
  return true;
}

void handleRoot() { if (authOK()) server.send_P(200, "text/html", PAGE); }
void handleStats() {
  if (!authOK()) return;
  char j[320];
  snprintf(j, sizeof(j),
           "{\"entries\":%u,\"queries\":%u,\"blocked\":%u,\"heap\":%u,\"uptime\":%u,\"status\":\"%s\"}",
           blCount, cntTotal, cntBlocked, ESP.getFreeHeap(), millis() / 1000, statusMsg);
  server.send(200, "application/json", j);
}
void handleUpdate() {
  if (!postOK()) return;
  if (updating) { server.send(409, "text/plain", "Update already running"); return; }
  updateRequested = true;
  server.send(200, "text/plain", "Update queued - watch the Status line (takes several minutes).");
}

File upFile; bool upOk = false, upDenied = false;
void handleUploadData() {
  HTTPUpload& u = server.upload();
  if (u.status == UPLOAD_FILE_START) {
    upDenied = updating || !server.authenticate(WEB_USER, WEB_PASS) ||
               server.header("X-Requested-With") != "c3-adblock";
    upOk = false;
    if (!upDenied) { LittleFS.remove(BL_TMP); upFile = LittleFS.open(BL_TMP, "w"); upOk = (bool)upFile; }
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!upDenied && upOk) {
      if (upFile.write(u.buf, u.currentSize) != u.currentSize) upOk = false;
      servicePoll(false);                            // keep DNS alive (not the web server: re-entrancy)
    }
  } else if (u.status == UPLOAD_FILE_END) {
    if (upFile) upFile.close();
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (upFile) upFile.close();
    LittleFS.remove(BL_TMP); upOk = false;
  }
}
void handleUploadDone() {
  if (upDenied) { server.send(updating ? 409 : 403, "text/plain", updating ? "Update running, try later" : "forbidden"); return; }
  if (!upOk) { LittleFS.remove(BL_TMP); server.send(500, "text/plain", "Upload failed (flash full?)"); return; }
  if (installTmp()) {
    setStatus("OK: uploaded %u domains", blCount);
    server.send(200, "text/plain", String("Installed ") + blCount + " entries.");
  } else {
    server.send(400, "text/plain", "Rejected: not a valid blocklist.bin (bad header / not sorted).");
  }
}

// ---------------- Wi-Fi ----------------
void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setTxPower(WIFI_POWER_8_5dBm);   // many SuperMini-type C3 boards fail to join at full power

  // Diagnostic: list what the board can actually see (2.4 GHz only).
  Serial.println("Scanning for networks...");
  int n = WiFi.scanNetworks();
  bool found = false;
  for (int i = 0; i < n; i++) {
    Serial.printf("  %-32s ch%-2d %4d dBm %s\n", WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i),
                  WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "open" : "secured");
    if (WiFi.SSID(i) == WIFI_SSID) found = true;
  }
  WiFi.scanDelete();
  if (found) Serial.println("OK: your SSID was found.");
  else Serial.println("WARNING: your SSID is NOT in the list above (wrong name, 5 GHz only, or too far).");

  WiFi.config(LOCAL_IP, GATEWAY, SUBNET, UPSTREAM_DNS);   // board's own resolver = upstream, never itself
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to Wi-Fi");
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED) {
    delay(500); Serial.print(".");
    if (millis() - start > 20000) {
      Serial.printf("\nNot connected, status=%d (1=SSID not found, 4=failed/wrong password, 6=disconnected). Retrying...\n",
                    (int)WiFi.status());
      WiFi.disconnect();
      delay(500);
      WiFi.begin(WIFI_SSID, WIFI_PASS);
      start = millis();
    }
  }
  Serial.printf("\nConnected. DNS server IP: %s\n", WiFi.localIP().toString().c_str());
}

void wifiCheck() {
  static uint32_t last = 0;
  if (WiFi.status() == WL_CONNECTED || millis() - last < 5000) return;
  last = millis();
  Serial.println("Wi-Fi lost, reconnecting...");
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

// ---------------- setup / loop ----------------
void setup() {
  Serial.begin(115200);
  delay(1000);
  if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed (wrong partition scheme?)");
  openBlocklist();
  Serial.printf("Flash blocklist: %u entries (+%u built-in)\n", blCount, (unsigned)N_CUSTOM);

  connectWifi();
  serverUdp.begin(DNS_PORT);
  upstreamUdp.begin(UPSTREAM_LOCAL_PORT);

  static const char* hdrs[] = {"X-Requested-With"};
  server.collectHeaders(hdrs, 1);
  server.on("/", HTTP_GET, handleRoot);
  server.on("/stats.json", HTTP_GET, handleStats);
  server.on("/update", HTTP_POST, handleUpdate);
  server.on("/upload", HTTP_POST, handleUploadDone, handleUploadData);
  server.begin();

  nextUpdateMs = millis() + (blCount ? UPDATE_INTERVAL_MS : 20000);   // no list yet -> fetch 20 s after boot
  if (strcmp(WEB_PASS, "CHANGE_ME") == 0) Serial.println("WARNING: change WEB_PASS in the sketch!");
  Serial.println("Ad blocker running. Web page: http://" + WiFi.localIP().toString() + "/");
}

uint32_t lastStats = 0;

void loop() {
  wifiCheck();
  dnsPoll();
  server.handleClient();

  if (WiFi.status() == WL_CONNECTED && !updating &&
      (updateRequested || (int32_t)(millis() - nextUpdateMs) >= 0)) {
    updateRequested = false;
    bool ok = updateBlocklist();
    nextUpdateMs = millis() + (ok ? UPDATE_INTERVAL_MS : 30UL * 60 * 1000);   // retry in 30 min on failure
  }

  if (millis() - lastStats > 60000) {
    lastStats = millis();
    Serial.printf("[stats] queries=%u blocked=%u list=%u heap=%u\n", cntTotal, cntBlocked, blCount, ESP.getFreeHeap());
  }
}
