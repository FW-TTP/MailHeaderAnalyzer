#!/usr/bin/env python3
import os
import sys
import threading
import webbrowser
import argparse
import logging
import re
import socket
import quopri
import whois
from flask import (
    Flask, request, render_template_string, url_for,
    session, send_file, Response
)
from email.parser import HeaderParser
from email.utils import parseaddr
from dateutil import parser as date_parser
from typing import List, Dict, Optional
import ipaddress
import geoip2.database
from collections import Counter
import tldextract
import io
import csv
import zipfile
from datetime import timezone

# -------- base directory (works in both normal & PyInstaller onefile) --------
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR  = os.path.join(BASE_DIR, 'data')
MMDB_PATH = os.path.join(DATA_DIR, 'GeoLite2-Country.mmdb')

TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mail Header Analyzer v0.4</title>
  <script src="{{ url_for('static', filename='tailwinds.16') }}"></script>
  <script src="{{ url_for('static', filename='chart.js') }}"></script>
<style media="print">
  @page { margin: 0; }
  form, nav, #export-btn, #export-menu, #clear-btn { display: none !important; }
  body { background: white; color: black; }
</style>
  <style>#drop-area.highlight{background:rgba(255,165,0,0.1);}</style>
</head>
<body class="bg-gray-900 text-gray-200">
  <div id="loading-overlay" class="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center hidden z-50">
    <svg class="animate-spin h-16 w-16 text-orange-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
    </svg>
    <p class="mt-4 text-xl text-orange-400">Processing...</p>
  </div>

  <nav class="bg-gray-800 shadow">
    <div class="container mx-auto p-4 flex justify-between items-center">
      <h1 class="text-3xl font-bold text-orange-500">Mail Header Analyzer v0.4</h1>
      <div class="space-x-2 relative">
        <button id="export-btn" class="px-4 py-2 bg-orange-500 text-gray-900 rounded hover:bg-orange-600">Export ▼</button>
        <ul id="export-menu" class="absolute right-0 mt-2 w-40 bg-gray-800 border border-gray-700 rounded shadow-lg hidden">
          <li><a href="{{ url_for('export', fmt='csv') }}" class="block px-4 py-2 hover:bg-gray-700">ZIP-CSV</a></li>
          <li><a href="{{ url_for('export', fmt='md') }}"  class="block px-4 py-2 hover:bg-gray-700">Markdown</a></li>
        </ul>
        <button id="clear-btn" onclick="window.location='/'"
                class="px-4 py-2 bg-gray-600 text-gray-200 rounded hover:bg-gray-700">Clear</button>
        <button onclick="window.print()"
                class="px-4 py-2 bg-gray-600 text-gray-200 rounded hover:bg-gray-700">Print / Save PDF</button>
      </div>
    </div>
  </nav>

<main class="container mx-auto py-8 px-2
             print:mx-0 print:px-0 print:max-w-none print:w-full">
    <form id="analyze-form" method="post" enctype="multipart/form-data" class="mb-8"
          onsubmit="document.getElementById('loading-overlay').classList.remove('hidden')">
      <div id="drop-area" class="w-full p-4 mb-4 bg-gray-800 border-2 border-dashed border-gray-600 rounded text-center">
              <p>Drag & Drop an .eml, .txt, or .msg file here</p>
       <!-- <input type="file" name="file" id="fileElem" accept=".eml,.txt,.msg" class="hidden"> -->
      </div>

      <textarea id="headers" name="headers"
                class="w-full h-48 p-2 bg-gray-800 border border-gray-700 rounded text-gray-100"
                placeholder="Paste mail headers here"
                required>{{ request.form.get('headers','') }}</textarea>
                
      <div class="mt-4">
        <button type="submit" class="px-4 py-2 bg-orange-500 text-gray-900 rounded hover:bg-orange-600">Analyze</button>
      </div>
    </form>

    {% if summary %}
    <!-- Summary -->
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <div class="text-gray-200 mb-4">
        <div class="mb-2"><span class="font-medium">Date:</span> {{ summary.Date }}</div>
        <div class="mb-2 grid grid-cols-2 gap-8">
          <div><span class="font-medium">From:</span> {{ summary.From }}</div>
          <div><span class="font-medium">To:</span> {{ summary.To }}</div>
        </div>
        <div class="mb-4"><span class="font-medium">Subject:</span> {{ summary.Subject }}</div>
        <hr class="border-gray-700 mb-4">
        <div class="grid grid-cols-2 gap-8">
          <div>
            <span class="font-medium"
                  title="SPF (Sender Policy Framework): which servers may send on behalf of this domain"
            >SPF:</span> {{ summary.SPF or 'N/A' }}
          </div>
          <div>
            <span class="font-medium"
                  title="Whois Created: when the sender’s domain was first registered"
            >Whois Created:</span> {{ summary.whois_created or 'N/A' }}
          </div>
        </div>
        <div class="grid grid-cols-2 gap-8 mt-2">
          <div>
            <span class="font-medium"
                  title="DMARC (Domain-based Message Authentication, Reporting & Conformance): policy for handling mail that fails SPF/DKIM"
            >DMARC:</span> {{ summary.DMARC or 'N/A' }}
          </div>
          <div>
            <span class="font-medium"
                  title="Whois Updated: when the sender’s domain record was last modified"
            >Whois Updated:</span> {{ summary.whois_updated or 'N/A' }}
          </div>
        </div>
        <div class="mt-4">
          <span class="font-medium"
                title="DKIM (DomainKeys Identified Mail): cryptographic signature verifying message integrity"
          >DKIM:</span> {{ summary.DKIM or 'N/A' }}
        </div>
      </div>
    </section>

    {% if whois_full %}
    <details class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <summary class="cursor-pointer text-2xl font-bold text-orange-500 mb-2">
        Full WHOIS for Senders Domain
      </summary>
      <pre class="whitespace-pre-wrap bg-gray-900 p-4 rounded text-gray-100">{{ whois_full }}</pre>
    </details>
    {% endif %}
    {% endif %}

    {% if entries %}
    <!-- Hop Delays -->
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Hop Delays</h2>
      <div class="relative w-full h-64 mb-8">
        <canvas id="hopDelayChart" class="absolute inset-0"></canvas>
      </div>
    </section>
    {% endif %}

    {% if entries %}
    <!-- Hop Journey -->
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Hop Journey</h2>
      <div class="overflow-auto">
        <table class="min-w-full table-auto border-collapse text-gray-100">
          <thead class="bg-gray-700"><tr>
            <th class="px-4 py-2">Hop</th><th>From</th><th>By</th>
            <th>Timestamp</th><th>Delay</th>
          </tr></thead>
          <tbody>
            {% for e in entries %}
            <tr class="border-t border-gray-700">
              <td class="px-4 py-2">{{ e.hop }}</td>
              <td class="px-4 py-2">{{ e.frm }}</td>
              <td class="px-4 py-2">{{ e.by }}</td>
              <td class="px-4 py-2">{{ e.timestamp }}</td>
              <td class="px-4 py-2">{{ e.duration }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if ips %}
    <!-- Extracted IPs -->
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Extracted IPs</h2>
      <div class="overflow-auto">
        <table class="min-w-full table-auto border-collapse text-gray-100">
          <thead class="bg-gray-700"><tr>
            <th class="px-4 py-2">IP Address</th><th>Count</th>
            <th>Version</th><th>Type</th><th>rDNS</th><th>Country</th>
          </tr></thead>
          <tbody>
            {% for ip in ips %}
            <tr class="border-t border-gray-700">
              <td class="px-4 py-2">{{ ip.address }}</td>
              <td class="px-4 py-2">{{ ip.count }}</td>
              <td class="px-4 py-2">v{{ ip.version }}</td>
              <td class="px-4 py-2">{{ ip.type }}</td>
              <td class="px-4 py-2">{{ ip.rdns or 'N/A' }}</td>
              <td class="px-4 py-2">{{ ip.country or 'N/A' }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if domains %}
    <!-- Extracted Domains -->
    <section class="bg-gray-800 shadow-lg rounded-lg p-6 mb-8">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Extracted Domains</h2>
      <div class="overflow-auto">
        <table class="min-w-full table-auto border-collapse text-gray-100">
          <thead class="bg-gray-700"><tr><th class="px-4 py-2">Domain</th><th>Count</th></tr></thead>
          <tbody>
            {% for d in domains %}
            <tr class="border-t border-gray-700">
              <td class="px-4 py-2">{{ d.domain }}</td><td class="px-4 py-2">{{ d.count }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

    {% if links %}
    <!-- Extracted Links -->
    <section class="bg-gray-800 shadow-lg rounded-lg p-6">
      <h2 class="text-2xl font-semibold mb-4 text-orange-500">Extracted Links</h2>
      <div class="overflow-auto">
        <table class="table-fixed w-full border-collapse text-gray-100">
          <thead class="bg-gray-700"><tr>
            <th class="w-1/4 px-2 py-1">Link Text</th>
            <th class="w-3/4 px-2 py-1">URL</th>
            <th class="w-16 px-2 py-1">Count</th>
          </tr></thead>
          <tbody>
            {% for l in links %}
            <tr class="border-t border-gray-700">
              <td class="px-2 py-1 break-words">{{ l.text|safe }}</td>
              <td class="px-2 py-1 break-words">{{ l.url }}</td>
              <td class="px-2 py-1 text-center">{{ l.count }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </section>
    {% endif %}

  </main>

  <script>
    // Drag & Drop
    const dropArea = document.getElementById('drop-area');
    const fileElem = document.getElementById('fileElem');
    dropArea.addEventListener('click', e => e.preventDefault());
    ['dragenter','dragover'].forEach(e =>
      dropArea.addEventListener(e, ev => { ev.preventDefault(); dropArea.classList.add('highlight'); })
    );
    ['dragleave','drop'].forEach(e =>
      dropArea.addEventListener(e, ev => { ev.preventDefault(); dropArea.classList.remove('highlight'); })
    );
     dropArea.addEventListener('drop', ev => {
       ev.preventDefault();
       dropArea.classList.remove('highlight');
       const files = ev.dataTransfer.files;
       if (!files.length) return;
       const ext = files[0].name.split('.').pop().toLowerCase();
       const headersEl = document.getElementById('headers');

       // build a new FileList so fileElem.files = ... actually works
       const dt = new DataTransfer();
       for (const f of files) dt.items.add(f);
       fileElem.files = dt.files;

       if (ext === 'msg') {
         // .msg goes straight to the server—clear textarea and show notice
         headersEl.value = '';
         headersEl.removeAttribute('required');
        headersEl.setAttribute(
          'placeholder',
          `Loaded ${files[0].name}. Click “Analyze” to parse headers.`
        );
         document.getElementById('file-info').textContent =
           `Loaded ${files[0].name}. Click “Analyze” to parse headers.`;
       } else {
         // inline‐read .eml / .txt
         const reader = new FileReader();
         reader.onload = e => { headersEl.value = e.target.result; };
         reader.readAsText(files[0]);
         document.getElementById('file-info').textContent = '';
          headersEl.setAttribute('required','required');
          headersEl.setAttribute('placeholder','Paste mail headers here');
       }
     });

    // Export menu toggle
    document.getElementById('export-btn').addEventListener('click', () => {
      document.getElementById('export-menu').classList.toggle('hidden');
    });

    {% if entries %}
    // Chart.js Hop Delays
    const ctx = document.getElementById('hopDelayChart').getContext('2d'),
          hops = {{ entries|tojson }};
    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: hops.map(h => `Hop ${h.hop}`),
        datasets: [{ data: hops.map(h => h.delay_secs), barThickness: 20 }]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        scales: {
          x: { beginAtZero: true, suggestedMax: {{ max_delay }} },
          y: { ticks: { color: '#fff' } }
        },
        plugins: { legend: { display: false } }
      }
    });
    {% endif %}
  </script>
</body>
</html>
'''

def _parse_date(text: str) -> Optional[float]:
    try:
        return date_parser.parse(text, fuzzy=True).timestamp()
    except:
        return None

def _format_duration(seconds: int) -> str:
    parts = []
    for name, cnt in [('hr',3600),('min',60),('sec',1)]:
        val, seconds = divmod(seconds, cnt)
        if val:
            parts.append(f"{val}{name}")
    return ' '.join(parts) or '0sec'

def parse_summary(raw: str) -> Dict[str, str]:
    hdr = HeaderParser().parsestr(raw)
    s = {'From':'','To':'','Subject':'','Date':''}
    s.update({k: hdr.get(k,'') for k in s})
    s.update({'SPF':None,'DKIM':None,'DMARC':None,'whois_created':None,'whois_updated':None})
    
        # --- normalize the Date header to UTC ISO format ---
    raw_date = s['Date']
    try:
        dt = date_parser.parse(raw_date, fuzzy=True)
        # if there's no tzinfo, assume it's already UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # convert to UTC (all good if already UTC)
        dt_utc = dt.astimezone(timezone.utc)
        s['Date'] = dt_utc.isoformat()   # e.g. "2025-05-01T23:44:50+00:00"
    except Exception:
        # leave s['Date'] as original if parsing fails
        pass
        
    for auth in hdr.get_all('Authentication-Results',[]):
        if m:=re.search(r'spf=(pass|fail|neutral|softfail|temperror|permerror)',auth,re.I):
            s['SPF']=m.group(1).lower()
        if m:=re.search(r'dkim=(pass|fail|neutral|policy|none)',auth,re.I):
            s['DKIM']=m.group(1).lower()
        if m:=re.search(r'dmarc=(pass|fail|bestguess|none)',auth,re.I):
            s['DMARC']=m.group(1).lower()
    if not s['SPF'] and hdr.get('Received-SPF'):
        s['SPF']=hdr.get('Received-SPF').split()[0]
    return s

def parse_received(raw: str) -> List[Dict]:
    hdr = HeaderParser().parsestr(raw)
    recs = hdr.get_all('Received') or []
    recs.reverse()
    hops, prev_ts = [], None
    for idx, r in enumerate(recs,1):
        parts = r.rsplit(';',1)
        ts_raw = parts[-1].strip() if parts[-1] else ''
        try:
            dt = date_parser.parse(ts_raw, fuzzy=True)
            # assume UTC if parser gives a naive datetime
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            # convert everything to UTC
            dt_utc = dt.astimezone(timezone.utc)
            iso = dt_utc.isoformat()        # "YYYY-MM-DDTHH:MM:SS+00:00"
            ts  = int(dt_utc.timestamp())   # seconds since epoch UTC
        except Exception:
            iso, ts = ts_raw, None

        delay = int(ts - prev_ts) if prev_ts and ts and ts > prev_ts else 0
        prev_ts = ts or prev_ts

        m = re.search(r'from\s+(.*?)\s+by\s+(.*?)(?:\s|$)', parts[0], re.I)
        frm, by = (m.group(1), m.group(2)) if m else ('', '')

        hops.append({
            'hop': idx,
            'frm': frm,
            'by': by,
            'timestamp': iso,
            'duration': _format_duration(delay),
            'delay_secs': delay
        })

    return hops


def extract_ips(raw: str) -> List[Dict]:
    joined = re.sub(r'=\r?\n', '', raw)
    joined_bytes = joined.encode('utf-8', errors='ignore')
    decoded_bytes = quopri.decodestring(joined_bytes)
    decoded = decoded_bytes.decode('utf-8', errors='ignore')
    #decoded = quopri.decodestring(joined).decode('utf-8', errors='ignore')

    ipv4_re = re.compile(
        r'(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
        r'(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])'
    )
    ipv6_re = re.compile(r'\[?([a-fA-F0-9:]+:+[a-fA-F0-9:%]+)\]?')

    found = []
    for regex in (ipv4_re, ipv6_re):
        for ip in regex.findall(decoded):
            ip_clean = ip.split('%')[0]
            try:
                obj = ipaddress.ip_address(ip_clean)
                found.append(obj.exploded)
            except ValueError:
                continue

    counts = Counter(found)
    reader = geoip2.database.Reader(MMDB_PATH)
    out = []
    for ip_str, cnt in counts.items():
        obj = ipaddress.ip_address(ip_str)
        rdns = None
        try:
            rdns = socket.gethostbyaddr(ip_str)[0]
        except:
            pass
        country = None
        if obj.is_global:
            try:
                country = reader.country(ip_str).country.name
            except:
                pass
        out.append({
            'address': ip_str,
            'count': cnt,
            'version': obj.version,
            'type': 'PUBLIC' if obj.is_global else 'PRIVATE' if obj.is_private else 'OTHER',
            'rdns': rdns,
            'country': country
        })
    reader.close()
    return out


def extract_domains(raw: str) -> List[Dict]:
    joined = re.sub(r'=\r?\n', '', raw)
    joined_bytes = joined.encode('utf-8', errors='ignore')
    decoded_bytes = quopri.decodestring(joined_bytes)
    decoded = decoded_bytes.decode('utf-8', errors='ignore')
    #decoded = quopri.decodestring(joined).decode('utf-8', errors='ignore')
    email_domains = re.findall(r'[\w\.-]+@([\w\.-]+)', decoded)
    url_domains = re.findall(r'https?://([\w\.-]+)', decoded)
    counts = Counter(email_domains + url_domains)
    return [{'domain': dom, 'count': cnt} for dom, cnt in counts.items()]


def extract_links(raw: str) -> List[Dict]:
    joined = re.sub(r'=\r?\n', '', raw)
    joined_bytes = joined.encode('utf-8', errors='ignore')
    decoded_bytes = quopri.decodestring(joined_bytes)
    decoded = decoded_bytes.decode('utf-8', errors='ignore')
    #decoded = quopri.decodestring(joined).decode('utf-8', errors='ignore')

    links = [
        {'text': m.group(2), 'url': m.group(1)}
        for m in re.finditer(
            r'<a[^>]*href=["\'](.*?)["\'][^>]*>(.*?)</a>',
            decoded,
            re.I
        )
    ]
    for m in re.finditer(r'(https?://[^\s<>"\']+)', decoded):
        url = m.group(1)
        if not any(l['url'] == url for l in links):
            links.append({'text': url, 'url': url})

    counts = Counter(l['url'] for l in links)
    uniq = []
    for l in links:
        if not any(u['url'] == l['url'] for u in uniq):
            uniq.append({
                'text': l['text'],
                'url': l['url'],
                'count': counts[l['url']]
            })
    return uniq


def create_app() -> Flask:
    app = Flask(__name__, static_folder=DATA_DIR, static_url_path='/static')
    app.secret_key = os.urandom(24)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        summary, entries, ips, domains, links = {}, [], [], [], []
        total_delay, max_delay, whois_full = '', 0, None

        if request.method == 'POST':
            # Determine raw headers from uploaded file or textarea
            f = request.files.get('file')
            if f and f.filename:
                name = f.filename.lower()
                data = f.read()
                if name.endswith('.msg'):
                    # --- .msg support via extract_msg ---
                    import tempfile, extract_msg, os

                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.msg')
                    tmp.write(data)
                    tmp.close()

                    msg = extract_msg.Message(tmp.name)
                    hdr_obj = msg.header

                    # Coerce hdr_obj into a plain string
                    if isinstance(hdr_obj, str):
                        raw = hdr_obj
                    elif hasattr(hdr_obj, 'as_string'):
                        raw = hdr_obj.as_string()
                    elif isinstance(hdr_obj, bytes):
                        raw = hdr_obj.decode('utf-8', errors='ignore')
                    else:
                        raw = str(hdr_obj or '')

                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
                else:
                    # .eml / .txt path
                    raw = data.decode('utf-8', errors='ignore')
            else:
                # No file → use textarea
                raw = request.form.get('headers', '')

            # Run your parsing pipeline
            summary = parse_summary(raw)
            entries = parse_received(raw)
            ips     = extract_ips(raw)
            domains = extract_domains(raw)
            links   = extract_links(raw)

            if entries:
                total_delay = _format_duration(sum(e['delay_secs'] for e in entries))
                max_delay   = max(e['delay_secs'] for e in entries)

            # WHOIS lookup (unchanged)
            email_addr = parseaddr(summary.get('From',''))[1]
            dom = email_addr.split('@',1)[1] if '@' in email_addr else None
            if dom:
                ext = tldextract.extract(dom)
                whois_dom = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                try:
                    w = whois.whois(whois_dom)
                    whois_full = getattr(w, 'text', None) or '\n'.join(f"{k}: {v}" for k, v in w.items())
                    for key, val in (('whois_created', w.creation_date),
                                     ('whois_updated', w.updated_date)):
                        if isinstance(val, list) and val:
                            val = val[0]
                        if isinstance(val, str):
                            try:
                                val = date_parser.parse(val)
                            except:
                                val = None
                        if hasattr(val, 'isoformat'):
                            if val.tzinfo is None:
                                val = val.replace(tzinfo=timezone.utc)
                            summary[key] = val.astimezone(timezone.utc).isoformat()
                        else:
                            summary[key] = None
                except Exception as e:
                    app.logger.warning(f"WHOIS failed for {whois_dom}: {e}")
                    summary['whois_created'] = summary['whois_updated'] = None

            # Store for export
            session['export_summary'] = summary
            session['export_entries'] = entries
            session['export_ips']     = ips
            session['export_domains'] = domains
            session['export_links']   = links

        return render_template_string(
            TEMPLATE,
            summary=summary,
            entries=entries,
            ips=ips,
            domains=domains,
            links=links,
            total_delay=total_delay,
            max_delay=max_delay,
            whois_full=whois_full
        )

    @app.route('/export/<fmt>')
    def export(fmt):
        summary = session.get('export_summary', {})
        entries = session.get('export_entries', [])
        ips     = session.get('export_ips', [])
        domains = session.get('export_domains', [])
        links   = session.get('export_links', [])

        # CSV → ZIP
        if fmt == 'csv':
            mem = io.BytesIO()
            with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
                # summary.csv
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(summary.keys())
                w.writerow(summary.values())
                z.writestr('summary.csv', buf.getvalue())

                # hops.csv
                if entries:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(entries[0].keys())
                    for e in entries:
                        w.writerow(e.values())
                    z.writestr('hops.csv', buf.getvalue())

                # ips.csv
                if ips:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(ips[0].keys())
                    for i in ips:
                        w.writerow(i.values())
                    z.writestr('ips.csv', buf.getvalue())

                # domains.csv
                if domains:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(domains[0].keys())
                    for d in domains:
                        w.writerow(d.values())
                    z.writestr('domains.csv', buf.getvalue())

                # links.csv
                if links:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(links[0].keys())
                    for l in links:
                        w.writerow(l.values())
                    z.writestr('links.csv', buf.getvalue())

            mem.seek(0)
            return send_file(
                mem,
                mimetype='application/zip',
                as_attachment=True,
                download_name='analysis_csvs.zip'
            )

        # Markdown
        if fmt == 'md':
            lines = ['# Mail Header Analysis', '', '## Summary', '| Field | Value |', '|---|---|']
            for key in ['Date','From','To','Subject','DKIM','DMARC','SPF','whois_created','whois_updated']:
                lines.append(f"| {key} | {summary.get(key,'')} |")
            lines.append('')
            if entries:
                lines += ['', '## Hop Journey', '| Hop | From | By | Timestamp | Delay |', '|---|---|---|---|---|']
                for e in entries:
                    lines.append(f"| {e['hop']} | {e['frm']} | {e['by']} | {e['timestamp']} | {e['duration']} |")
            lines.append('')
            if ips:
                lines += ['', '## Extracted IPs', '| IP | Count | Version | Type | rDNS | Country |', '|---|---|---|---|---|']
                for i in ips:
                    lines.append(f"| {i['address']} | {i['count']} | {i['version']} | {i['type']} | {i['rdns'] or ''} | {i['country'] or ''} |")
            lines.append('')
            if domains:
                lines += ['', '## Extracted Domains', '| Domain | Count |', '|---|---|---|']
                for d in domains:
                    lines.append(f"| {d['domain']} | {d['count']} |")
            lines.append('')
            if links:
                lines += ['', '## Extracted Links', '| Text | URL | Count |', '|---|---|---|']
                for l in links:
                    lines.append(f"| {l['text']} | {l['url']} | {l['count']} |")
            md = '\n'.join(lines)
            return Response(
                md,
                mimetype='text/markdown',
                headers={'Content-Disposition':'attachment; filename=analysis.md'}
            )

        return "Unsupported format", 400

    return app

    app = Flask(__name__, static_folder=DATA_DIR, static_url_path='/static')
    app.secret_key = os.urandom(24)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        summary, entries, ips, domains, links = {}, [], [], [], []
        total_delay, max_delay, whois_full = '', 0, None

        if request.method == 'POST':
            # Load raw headers (support .msg via extract_msg)
            if 'file' in request.files and request.files['file'].filename:
                f = request.files['file']
                fname = f.filename.lower()
                if fname.endswith('.msg'):
                    import tempfile, extract_msg, os

                    # write uploaded bytes to a temp .msg
                    data = f.read()
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.msg')
                    tmp.write(data)
                    tmp.close()

                    # parse the Outlook .msg
                    msg = extract_msg.Message(tmp.name)
                    # extract_msg.Message.header is the raw header string
                    raw = msg.header or ''

                    # clean up
                    try: os.unlink(tmp.name)
                    except: pass
                else:
                    # existing .eml / .txt handling
                    raw = f.read().decode('utf-8', errors='ignore')
            else:
                raw = request.form['headers']

            # Parse
            summary = parse_summary(raw)
            entries = parse_received(raw)
            ips     = extract_ips(raw)
            domains = extract_domains(raw)
            links   = extract_links(raw)

            if entries:
                total_delay = _format_duration(sum(e['delay_secs'] for e in entries))
                max_delay   = max(e['delay_secs'] for e in entries)

            # WHOIS
            email_addr = parseaddr(summary['From'])[1]
            dom = email_addr.split('@', 1)[1] if '@' in email_addr else None
            if dom:
                ext = tldextract.extract(dom)
                whois_dom = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                try:
                    w = whois.whois(whois_dom)
                    whois_full = getattr(w, 'text', None) or '\n'.join(f"{k}: {v}" for k, v in w.items())
                    for key, val in (('whois_created', w.creation_date),
                                     ('whois_updated', w.updated_date)):
                        if isinstance(val, list) and val:
                            val = val[0]
                        if isinstance(val, str):
                            try:
                                val = date_parser.parse(val)
                            except:
                                val = None
                        if hasattr(val, 'isoformat'):
                            if val.tzinfo is None:
                                val = val.replace(tzinfo=timezone.utc)
                            summary[key] = val.astimezone(timezone.utc).isoformat()
                        else:
                            summary[key] = None
                except Exception as e:
                    app.logger.warning(f"WHOIS failed for {whois_dom}: {e}")
                    summary['whois_created'] = None
                    summary['whois_updated'] = None

            # Save for export
            session['export_summary'] = summary
            session['export_entries'] = entries
            session['export_ips']     = ips
            session['export_domains'] = domains
            session['export_links']   = links

        return render_template_string(
            TEMPLATE,
            summary=summary,
            entries=entries,
            ips=ips,
            domains=domains,
            links=links,
            total_delay=total_delay,
            max_delay=max_delay,
            whois_full=whois_full
        )

    @app.route('/export/<fmt>')
    def export(fmt):
        summary = session.get('export_summary', {})
        entries = session.get('export_entries', [])
        ips     = session.get('export_ips', [])
        domains = session.get('export_domains', [])
        links   = session.get('export_links', [])

        # CSV → ZIP
        if fmt == 'csv':
            mem = io.BytesIO()
            with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
                # summary.csv
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(summary.keys())
                w.writerow(summary.values())
                z.writestr('summary.csv', buf.getvalue())

                # hops.csv
                if entries:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(entries[0].keys())
                    for e in entries:
                        w.writerow(e.values())
                    z.writestr('hops.csv', buf.getvalue())

                # ips.csv
                if ips:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(ips[0].keys())
                    for i in ips:
                        w.writerow(i.values())
                    z.writestr('ips.csv', buf.getvalue())

                # domains.csv
                if domains:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(domains[0].keys())
                    for d in domains:
                        w.writerow(d.values())
                    z.writestr('domains.csv', buf.getvalue())

                # links.csv
                if links:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(links[0].keys())
                    for l in links:
                        w.writerow(l.values())
                    z.writestr('links.csv', buf.getvalue())

            mem.seek(0)
            return send_file(
                mem,
                mimetype='application/zip',
                as_attachment=True,
                download_name='analysis_csvs.zip'
            )

        # Markdown
        if fmt == 'md':
            lines = ['# Mail Header Analysis', '', '## Summary', '| Field | Value |', '|---|---|']
            for key in ['Date','From','To','Subject','DKIM','DMARC','SPF','whois_created','whois_updated']:
                lines.append(f"| {key} | {summary.get(key,'')} |")
            lines.append('')
            if entries:
                lines += ['', '## Hop Journey', '| Hop | From | By | Timestamp | Delay |', '|---|---|---|---|---|']
                for e in entries:
                    lines.append(f"| {e['hop']} | {e['frm']} | {e['by']} | {e['timestamp']} | {e['duration']} |")
            lines.append('')
            if ips:
                lines += ['', '## Extracted IPs', '| IP | Count | Version | Type | rDNS | Country |', '|---|---|---|---|---|---|']
                for i in ips:
                    lines.append(f"| {i['address']} | {i['count']} | {i['version']} | {i['type']} | {i['rdns'] or ''} | {i['country'] or ''} |")
            lines.append('')
            if domains:
                lines += ['', '## Extracted Domains', '| Domain | Count |', '|---|---|---|']
                for d in domains:
                    lines.append(f"| {d['domain']} | {d['count']} |")
            lines.append('')
            if links:
                lines += ['', '## Extracted Links', '| Text | URL | Count |', '|---|---|---|']
                for l in links:
                    lines.append(f"| {l['text']} | {l['url']} | {l['count']} |")
            md = '\n'.join(lines)
            return Response(
                md,
                mimetype='text/markdown',
                headers={'Content-Disposition':'attachment; filename=analysis.md'}
            )

        return "Unsupported format", 400

    return app

    app = Flask(__name__, static_folder=DATA_DIR, static_url_path='/static')
    app.secret_key = os.urandom(24)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.route('/', methods=['GET', 'POST'])
    def index():
        summary, entries, ips, domains, links = {}, [], [], [], []
        total_delay, max_delay, whois_full = '', 0, None

        if request.method == 'POST':
            if 'file' in request.files and request.files['file'].filename:
                f = request.files['file']
                fname = f.filename.lower()
                if fname.endswith('.msg'):
                    import tempfile, extract_msg, os

                    data = f.read()
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.msg')
                    tmp.write(data)
                    tmp.close()

                    msg = extract_msg.Message(tmp.name)
                    raw = msg.header or ''

                    try: os.unlink(tmp.name)
                    except: pass
                else:
                    raw = f.read().decode('utf-8', errors='ignore')
            else:
                # no file uploaded → use the textarea contents
                raw = request.form.get('headers', '')

            # Parse
            summary = parse_summary(raw)
            entries = parse_received(raw)
            ips     = extract_ips(raw)
            domains = extract_domains(raw)
            links   = extract_links(raw)

            if entries:
                total_delay = _format_duration(sum(e['delay_secs'] for e in entries))
                max_delay   = max(e['delay_secs'] for e in entries)

            # WHOIS
            email_addr = parseaddr(summary['From'])[1]
            dom = email_addr.split('@', 1)[1] if '@' in email_addr else None
            if dom:
                ext = tldextract.extract(dom)
                whois_dom = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
                try:
                    w = whois.whois(whois_dom)
                    whois_full = getattr(w, 'text', None) or '\n'.join(f"{k}: {v}" for k, v in w.items())
                    for key, val in (('whois_created', w.creation_date),
                                     ('whois_updated', w.updated_date)):
                        if isinstance(val, list) and val:
                            val = val[0]
                        if isinstance(val, str):
                            try:
                                val = date_parser.parse(val)
                            except:
                                val = None
                        if hasattr(val, 'isoformat'):
                            if val.tzinfo is None:
                                val = val.replace(tzinfo=timezone.utc)
                            summary[key] = val.astimezone(timezone.utc).isoformat()
                        else:
                            summary[key] = None
                except Exception as e:
                    app.logger.warning(f"WHOIS failed for {whois_dom}: {e}")
                    summary['whois_created'] = None
                    summary['whois_updated'] = None

            # Save for export
            session['export_summary'] = summary
            session['export_entries'] = entries
            session['export_ips']     = ips
            session['export_domains'] = domains
            session['export_links']   = links

        return render_template_string(
            TEMPLATE,
            summary=summary,
            entries=entries,
            ips=ips,
            domains=domains,
            links=links,
            total_delay=total_delay,
            max_delay=max_delay,
            whois_full=whois_full
        )

    @app.route('/export/<fmt>')
    def export(fmt):
        summary = session.get('export_summary', {})
        entries = session.get('export_entries', [])
        ips     = session.get('export_ips', [])
        domains = session.get('export_domains', [])
        links   = session.get('export_links', [])

        # CSV → ZIP
        if fmt == 'csv':
            mem = io.BytesIO()
            with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(['Field', 'Value'])
                for key in ['Date','From','To','Subject','DKIM','DMARC','SPF','whois_created','whois_updated']:
                    w.writerow([key, summary.get(key, '')])
                z.writestr('summary.csv', buf.getvalue())

                if entries:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(entries[0].keys())
                    for e in entries:
                        w.writerow(e.values())
                    z.writestr('hops.csv', buf.getvalue())

                if ips:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(ips[0].keys())
                    for i in ips:
                        w.writerow(i.values())
                    z.writestr('ips.csv', buf.getvalue())

                if domains:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(domains[0].keys())
                    for d in domains:
                        w.writerow(d.values())
                    z.writestr('domains.csv', buf.getvalue())

                if links:
                    buf = io.StringIO()
                    w = csv.writer(buf)
                    w.writerow(links[0].keys())
                    for l in links:
                        w.writerow(l.values())
                    z.writestr('links.csv', buf.getvalue())

            mem.seek(0)
            return send_file(
                mem,
                mimetype='application/zip',
                as_attachment=True,
                download_name='analysis_csvs.zip'
            )

        # Markdown
        if fmt == 'md':
            lines = ['# Mail Header Analysis', '', '## Summary', '| Field | Value |', '|---|---|']
            for key in ['Date','From','To','Subject','DKIM','DMARC','SPF','whois_created','whois_updated']:
                lines.append(f"| {key} | {summary.get(key,'')} |")
            lines.append('')
            if entries:
                lines += ['', '## Hop Journey', '| Hop | From | By | Timestamp | Delay |', '|---|---|---|---|---|']
                for e in entries:
                    lines.append(f"| {e['hop']} | {e['frm']} | {e['by']} | {e['timestamp']} | {e['duration']} |")
            lines.append('')
            if ips:
                lines += ['', '## Extracted IPs', '| IP | Count | Version | Type | rDNS | Country |', '|---|---|---|---|---|---|']
                for i in ips:
                    lines.append(f"| {i['address']} | {i['count']} | {i['version']} | {i['type']} | {i['rdns'] or ''} | {i['country'] or ''} |")
            lines.append('')
            if domains:
                lines += ['', '## Extracted Domains', '| Domain | Count |', '|---|---|']
                for d in domains:
                    lines.append(f"| {d['domain']} | {d['count']} |")
            lines.append('')
            if links:
                lines += ['', '## Extracted Links', '| Text | URL | Count |', '|---|---|---|']
                for l in links:
                    lines.append(f"| {l['text']} | {l['url']} | {l['count']} |")
            md = '\n'.join(lines)
            return Response(
                md,
                mimetype='text/markdown',
                headers={'Content-Disposition':'attachment; filename=analysis.md'}
            )

        return "Unsupported format", 400

    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mail Header Analyzer')
    parser.add_argument('-d','--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-b','--bind', default='127.0.0.1', help='Bind address')
    parser.add_argument('-p','--port', type=int, default=5001, help='Port number')
    args = parser.parse_args()

    app = create_app()
    if args.debug:
        app.debug = True

    threading.Timer(1, lambda: webbrowser.open_new(f"http://{args.bind}:{args.port}/")).start()
    app.run(host=args.bind, port=args.port, use_reloader=False)

