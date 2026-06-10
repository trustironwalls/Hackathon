const CHALLENGES = require('./challenges');

function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function resolvePath(p, cwd) {
  if (!p || p === '~') return '/home/operator';
  if (p.startsWith('~/')) p = '/home/operator' + p.slice(1);
  if (!p.startsWith('/')) p = (cwd === '/' ? '/' : cwd + '/') + p;
  const parts = p.split('/').filter(Boolean), stack = [];
  for (const pt of parts) {
    if (pt === '.') continue;
    if (pt === '..') stack.pop();
    else stack.push(pt);
  }
  return '/' + stack.join('/');
}

function fsnode(p, cwd, fs) {
  return fs[resolvePath(p, cwd)] || null;
}

function colorEntry(name, n) {
  if (!n) return esc(name);
  if (n.type === 'dir') return `<span class="t-dir">${esc(name)}/</span>`;
  if (n.type === 'symlink') return `<span class="t-link">${esc(name)} -> ${esc(n.target)}</span>`;
  if (n.perms && n.perms.includes('x')) return `<span class="t-exe">${esc(name)}</span>`;
  if (name.startsWith('.')) return `<span class="t-dim">${esc(name)}</span>`;
  return `<span class="t-out">${esc(name)}</span>`;
}

function executeCommand(raw, currentCwd, fs, solvedFlags) {
  let cwd = currentCwd || '/home/operator';
  const output = [];
  const capturedFlags = [];

  function tpr(html) {
    output.push(html);
  }
  function tprt(txt, c = 't-out') {
    tpr(`<span class="${c}">${esc(txt)}</span>`);
  }
  function tperr(m) {
    tpr(`<span class="t-err">${esc(m)}</span>`);
  }

  const input = raw.trim();
  if (!input) return { output: '', newCwd: cwd, fsState: fs, capturedFlags };

  if (input.includes('|')) {
    pipeCmd(input, cwd, fs, tpr, tprt, tperr);
    autoDetect(output, solvedFlags, capturedFlags);
    return { output: output.join('\n'), newCwd: cwd, fsState: fs, capturedFlags };
  }

  const toks = input.split(/\s+/);
  const cmd = toks[0];
  const args = toks.slice(1);

  switch (cmd) {
    case 'ls': {
      const ha = args.some(a => a.startsWith('-') && a.includes('a'));
      const la = args.some(a => a.startsWith('-') && a.includes('l'));
      const target = args.find(a => !a.startsWith('-')) || cwd;
      const p = resolvePath(target, cwd);
      const n = fs[p];
      if (!n) {
        tperr(`ls: cannot access '${target}': No such file or directory`);
        break;
      }
      if (n.type === 'file') {
        tpr(colorEntry(p.split('/').pop(), n));
        break;
      }
      let ch = (n.children || []).slice();
      if (!ha) ch = ch.filter(c => !c.startsWith('.'));
      if (!ch.length) break;
      const lines = ch.map(name => {
        const cp = p === '/' ? '/' + name : p + '/' + name;
        const cn = fs[cp];
        if (la) {
          const pm = cn ? (cn.perms || (cn.type === 'dir' ? 'drwxr-xr-x' : '-rw-r--r--')) : '-rw-r--r--';
          const ow = cn && cn.owner ? cn.owner : 'root';
          const sz = cn && cn.type === 'file' ? (cn.content || '').length : 4096;
          return `<span class="t-out">${pm} 1 ${ow} ${ow} ${String(sz).padStart(7)} Jan 20 10:23 ${colorEntry(name, cn)}</span>`;
        }
        return colorEntry(name, cn);
      });
      tpr(la ? lines.join('\n') : lines.join('  '));
      break;
    }
    case 'cd': {
      const t = args[0] || '/home/operator';
      const p = resolvePath(t, cwd);
      const n = fs[p];
      if (!n) {
        tperr(`bash: cd: ${t}: No such file or directory`);
        break;
      }
      if (n.type !== 'dir') {
        tperr(`bash: cd: ${t}: Not a directory`);
        break;
      }
      cwd = p;
      break;
    }
    case 'cat': {
      const files = args.filter(a => !a.startsWith('-'));
      if (!files.length) {
        tperr('cat: missing operand');
        break;
      }
      files.forEach(f => {
        const p = resolvePath(f, cwd);
        const n = fs[p];
        if (!n) {
          tperr(`cat: ${f}: No such file or directory`);
          return;
        }
        if (n.type === 'dir') {
          tperr(`cat: ${f}: Is a directory`);
          return;
        }
        if (n.type === 'symlink') {
          const tn = fs[n.target];
          if (tn && tn.type === 'file') {
            tpr(`<span class="t-out">${esc(tn.content || '')}</span>`);
          } else {
            tperr(`cat: ${f}: broken symlink`);
          }
          return;
        }
        if ((n.content || '').startsWith('Permission denied')) {
          tperr(n.content);
          return;
        }
        const c = esc(n.content || '').replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
        tpr(`<span class="t-out">${c}</span>`);
      });
      break;
    }
    case 'head': {
      const ni = args.indexOf('-n');
      const nVal = ni > -1 ? parseInt(args[ni + 1]) || 10 : 10;
      const f = args.find(a => !a.startsWith('-') && isNaN(parseInt(a)));
      if (!f) {
        tperr('head: missing file');
        break;
      }
      const nd = fs[resolvePath(f, cwd)];
      if (!nd || nd.type === 'dir') {
        tperr(`head: ${f}: No such file`);
        break;
      }
      tpr(`<span class="t-out">${esc((nd.content || '').split('\n').slice(0, nVal).join('\n'))}</span>`);
      break;
    }
    case 'tail': {
      const ni = args.indexOf('-n');
      const nVal = ni > -1 ? parseInt(args[ni + 1]) || 10 : 10;
      const f = args.find(a => !a.startsWith('-') && isNaN(parseInt(a)));
      if (!f) {
        tperr('tail: missing file');
        break;
      }
      const nd = fs[resolvePath(f, cwd)];
      if (!nd || nd.type === 'dir') {
        tperr(`tail: ${f}: No such file`);
        break;
      }
      const c = esc((nd.content || '').split('\n').slice(-nVal).join('\n')).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
      tpr(`<span class="t-out">${c}</span>`);
      break;
    }
    case 'find': {
      const ni = args.indexOf('-name');
      const pat = ni > -1 ? args[ni + 1] : null;
      const ti = args.indexOf('-type');
      const tf = ti > -1 ? args[ti + 1] : null;
      const pi = args.indexOf('-perm');
      const pv = pi > -1 ? args[pi + 1] : null;
      const newI = args.indexOf('-newer');
      let startP = args.find(a => !a.startsWith('-') && !['name', 'type', 'perm', 'newer', 'readable', 'mtime'].includes(a)) || cwd;
      if (startP.startsWith('-')) startP = cwd;
      if (pv && (pv.includes('4000') || pv === '-4000')) {
        const suid = Object.entries(fs).filter(([p, n]) => n.type === 'file' && (n.perms || '').includes('s')).map(([p]) => p);
        tpr(['<span class="t-out">/usr/bin/passwd\n/usr/bin/sudo\n/bin/su\n/usr/bin/pkexec\n' + (suid.join('\n'))]
          .join('').replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`));
        break;
      }
      if (newI > -1) {
        tpr('<span class="t-out">/var/log/latest_evidence.log\n/tmp/xf3r_9k2.dat</span>');
        break;
      }
      if (pv === '777' || pv === '-0002') {
        const ww = Object.entries(fs).filter(([p, n]) => n.type === 'file' && (n.perms || '').includes('rwxrwxrwx')).map(([p]) => p);
        tpr((ww.length ? ww : '[none found]').toString());
        break;
      }
      const base = resolvePath(startP, cwd);
      const results = [];
      function walk(p) {
        const n = fs[p];
        if (!n) return;
        const name = p.split('/').pop();
        let ok = true;
        if (pat) {
          const re = new RegExp('^' + pat.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
          ok = ok && re.test(name);
        }
        if (tf) ok = ok && ((tf === 'f' && n.type === 'file') || (tf === 'd' && n.type === 'dir'));
        if (ok) results.push(p);
        if (n.type === 'dir' && n.children) n.children.forEach(c => walk(p === '/' ? '/' + c : p + '/' + c));
      }
      walk(base);
      if (results.length) tpr(results.map(r => `<span class="t-out">${esc(r)}</span>`).join('\n'));
      break;
    }
    case 'grep': {
      const flags = args.filter(a => a.startsWith('-'));
      const nf = args.filter(a => !a.startsWith('-'));
      if (nf.length < 2) {
        tperr('grep: usage: grep [flags] PATTERN FILE');
        break;
      }
      const pat = nf[0].replace(/['"]/g, '');
      const files = nf.slice(1);
      const rec = flags.includes('-r') || flags.includes('-R');
      const ci = flags.includes('-i');
      const fps = rec ? Object.keys(fs).filter(p => fs[p].type === 'file') : files.map(f => resolvePath(f, cwd));
      const results = [];
      fps.forEach(fp => {
        const n = fs[fp];
        if (!n || n.type !== 'file') return;
        (n.content || '').split('\n').forEach((line, i) => {
          const re = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, (m) => m === '*' ? '.*' : '\\' + m), ci ? 'i' : '');
          if (re.test(line)) {
            const pref = (rec || files.length > 1) ? `<span style="color:var(--teal)">${esc(fp)}:</span>` : '';
            const lp = flags.includes('-n') ? `<span style="color:var(--yellow)">${i + 1}:</span>` : '';
            const lc = esc(line).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
            results.push(pref + lp + `<span class="t-out">${lc}</span>`);
          }
        });
      });
      if (results.length) tpr(results.join('\n'));
      break;
    }
    case 'awk': {
      const fi = args.indexOf('-F');
      const sep = fi > -1 ? args[fi + 1].replace(/['"]/g, '') : ' ';
      const fA = args[args.length - 1];
      if (!fA || fA.startsWith("'") || fA.startsWith('"')) {
        tprt('[awk: specify a file or use a pipe]');
        break;
      }
      const n = fs[resolvePath(fA, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`awk: ${fA}: No such file`);
        break;
      }
      const prog = args.find(a => a.includes('print')) || '{print}';
      const condM = prog.match(/\$(\d+)==["']?([^"'\{]+)["']?\{/);
      const flds = (prog.match(/\$(\d+)/g) || []);
      (n.content || '').split('\n').forEach(line => {
        const fs2 = line.split(sep === ' ' ? /\s+/ : new RegExp(sep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
        if (condM) {
          const ci2 = parseInt(condM[1]) - 1;
          if (fs2[ci2] !== condM[2].trim()) return;
        }
        const outText = flds.length ? flds.map(f => fs2[parseInt(f.slice(1)) - 1] || '').join(' ') : line;
        const oc = esc(outText).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
        tpr(`<span class="t-out">${oc}</span>`);
      });
      break;
    }
    case 'cut': {
      const di = args.indexOf('-d');
      const sep = di > -1 ? args[di + 1].replace(/['"]/g, '') : '\t';
      const fli = args.indexOf('-f');
      const fi = fli > -1 ? parseInt(args[fli + 1]) - 1 : 0;
      const fA = args.find(a => !a.startsWith('-') && a !== sep && isNaN(parseInt(a)));
      if (!fA) {
        tperr('cut: missing file');
        break;
      }
      const n = fs[resolvePath(fA, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`cut: ${fA}: No such file`);
        break;
      }
      (n.content || '').split('\n').forEach(l => tpr(`<span class="t-out">${esc(l.split(sep)[fi] || '')}</span>`));
      break;
    }
    case 'wc': {
      const f = args.find(a => !a.startsWith('-'));
      if (!f) {
        tperr('wc: missing file');
        break;
      }
      const n = fs[resolvePath(f, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`wc: ${f}: No such file`);
        break;
      }
      const c = n.content || '';
      tprt(`${c.split('\n').length} ${c.split(/\s+/).filter(Boolean).length} ${c.length} ${f}`);
      break;
    }
    case 'rev': {
      const f = args.find(a => !a.startsWith('-'));
      if (!f) {
        tperr('rev: missing file');
        break;
      }
      const n = fs[resolvePath(f, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`rev: ${f}: No such file`);
        break;
      }
      (n.content || '').split('\n').forEach(l => {
        const r = esc(l.split('').reverse().join('')).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
        tpr(`<span class="t-out">${r}</span>`);
      });
      break;
    }
    case 'base64': {
      const dec = args.includes('-d');
      const f = args.find(a => !a.startsWith('-'));
      if (!f) {
        tperr('base64: missing file');
        break;
      }
      const n = fs[resolvePath(f, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`base64: ${f}: No such file`);
        break;
      }
      if (dec) {
        try {
          const result = Buffer.from((n.content || '').trim().split('\n')[0], 'base64').toString('utf-8');
          const rc = esc(result).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
          tpr(`<span class="t-out">${rc}</span>`);
        } catch (e) {
          tperr('base64: invalid encoded data');
        }
      } else {
        tprt(Buffer.from(n.content || '').toString('base64'));
      }
      break;
    }
    case 'xxd': {
      const rp = args.includes('-r') && args.includes('-p');
      const f = args.find(a => !a.startsWith('-'));
      if (!f) {
        tperr('xxd: missing file');
        break;
      }
      const n = fs[resolvePath(f, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`xxd: ${f}: No such file`);
        break;
      }
      if (rp) {
        const hex = (n.content || '').replace(/\s/g, '').replace(/[^0-9a-fA-F]/g, '');
        try {
          const bytes = hex.match(/.{1,2}/g) || [];
          const result = bytes.map(b => String.fromCharCode(parseInt(b, 16))).join('');
          const rc = esc(result).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
          tpr(`<span class="t-out">${rc}</span>`);
        } catch (e) {
          tperr('xxd: decode error');
        }
      } else {
        const c = (n.content || '').slice(0, 48);
        let outText = '00000000: ';
        for (let i = 0; i < c.length; i++) outText += c.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
        tprt(outText);
      }
      break;
    }
    case 'strings': {
      const f = args.find(a => !a.startsWith('-'));
      if (!f) {
        tperr('strings: missing file');
        break;
      }
      const n = fs[resolvePath(f, cwd)];
      if (!n || n.type === 'dir') {
        tperr(`strings: ${f}: No such file`);
        break;
      }
      const matches = (n.content || '').match(/[\x20-\x7E]{4,}/g) || [];
      const outText = matches.map(s => esc(s).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`));
      if (outText.length) tpr(outText.map(s => `<span class="t-out">${s}</span>`).join('\n'));
      break;
    }
    case 'tr': {
      const sets = args.filter(a => !a.startsWith('-'));
      const fA = args[args.length - 1];
      const n = fs[resolvePath(fA, cwd)];
      if (!n || n.type === 'dir') {
        tprt('[tr: pipe input required, e.g. cat file | tr a-z n-za-m]');
        break;
      }
      if (sets.length >= 2) {
        const from = sets[0].replace(/['"]/g, '');
        const to = sets[1].replace(/['"]/g, '');
        const expand = s => {
          let r = '';
          for (let i = 0; i < s.length; i++) {
            if (s[i + 1] === '-' && s[i + 2]) {
              const a = s.charCodeAt(i), b = s.charCodeAt(i + 2);
              for (let c = a; c <= b; c++) r += String.fromCharCode(c);
              i += 2;
            } else r += s[i];
          }
          return r;
        };
        const fe = expand(from), te = expand(to);
        const result = (n.content || '').split('').map(c => {
          const i = fe.indexOf(c);
          return i > -1 ? (te[i] || c) : c;
        }).join('');
        const rc = esc(result).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
        tpr(`<span class="t-out">${rc}</span>`);
      }
      break;
    }
    case 'python':
    case 'python3': {
      const ci = args.indexOf('-c');
      if (ci > -1) {
        const code = args.slice(ci + 1).join(' ').replace(/^['"]|['"]$/g, '');
        if (code.includes('fromhex')) {
          const hm = code.match(/fromhex\(['"]([\da-fA-F]+)['"]\)/);
          if (hm) {
            try {
              const bytes = hm[1].match(/.{2}/g) || [];
              const result = bytes.map(b => String.fromCharCode(parseInt(b, 16))).join('');
              const rc = esc(result).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
              tpr(`<span class="t-out">${rc}</span>`);
            } catch (e) {
              tperr('python3: invalid hex');
            }
          } else {
            tprt('[python3: hex decode simulated — wrap hex in quotes]');
          }
        } else if (code.includes('print')) {
          tprt('[python3: ' + code.slice(0, 60) + ']');
        } else {
          tprt('[python3: simulated]');
        }
      } else {
        tprt('[python3: interactive mode not supported — use -c]');
      }
      break;
    }
    case 'curl': {
      const url = args.find(a => !a.startsWith('-')) || '';
      const headers = args.includes('-I') || args.includes('-i');
      if (url.includes('/api/v1/debug') || url === 'debug') {
        tpr(`<span class="t-out">HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "status": "debug",\n  "version": "3.1.0",\n  "flag": "<span class="t-flag">FLAG{4p1_d3bug_3ndp01nt}</span>",\n  "uptime": 86400\n}</span>`);
      } else if (headers) {
        tpr(`<span class="t-out">HTTP/1.1 200 OK\nContent-Type: text/html\nX-Powered-By: DEEBUG-CTF/3.1\nX-Flag: <span class="t-flag">FLAG{h3ad3r_1nj3ct10n}</span>\nContent-Length: 4096\nConnection: keep-alive</span>`);
      } else {
        tpr(`<span class="t-out">HTTP/1.1 200 OK\n\n&lt;!DOCTYPE html&gt;&lt;html&gt;&lt;body&gt;DEEBUG CTF&lt;/body&gt;&lt;/html&gt;</span>`);
      }
      break;
    }
    case 'wget':
      tprt('[simulated: file downloaded]');
      break;
    case 'pwd':
      tprt(cwd);
      break;
    case 'whoami':
      tprt('root');
      break;
    case 'id':
      tprt('uid=0(root) gid=0(root) groups=0(root)');
      break;
    case 'hostname':
      tprt('opsec-ctf');
      break;
    case 'uname':
      tprt(args.includes('-a') ? 'Linux opsec-ctf 6.1.0-kali9-amd64 #1 SMP PREEMPT Debian x86_64 GNU/Linux' : 'Linux');
      break;
    case 'date':
      tprt(new Date().toString());
      break;
    case 'clear':
      tpr('[clear]');
      break;
    case 'history':
      tprt('[history commands are stored client-side]');
      break;
    case 'env':
      tpr('<span class="t-out">PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/home/operator\nUSER=operator\nSHELL=/bin/bash\nDEPLOY_KEY=FLAG{3xp0rt_v4r_l34k3d}</span>');
      break;
    case 'ps':
      tpr('<span class="t-out">  PID TTY      TIME CMD\n    1 ?    00:00:01 systemd\n  900 ?    00:00:00 sshd\n 1234 pts/0 00:00:00 bash\n 1300 pts/0 00:00:00 ps</span>');
      break;
    case 'ss':
      tpr('<span class="t-out">Netid  State   Local:Port\ntcp    LISTEN  0.0.0.0:22\ntcp    LISTEN  0.0.0.0:80\ntcp    LISTEN  127.0.0.1:3306</span>');
      break;
    case 'ip':
      if (args[0] === 'a' || args[0] === 'addr') {
        tprt('2: eth0: inet 10.0.0.50/24\n3: lo: inet 127.0.0.1/8');
      } else {
        tperr('ip: unknown subcommand');
      }
      break;
    case 'echo':
      tprt(args.join(' '));
      break;
    case 'mkdir':
      args.filter(a => !a.startsWith('-')).forEach(d => {
        const p = resolvePath(d, cwd);
        fs[p] = { type: 'dir', children: [] };
        const par = p.substring(0, p.lastIndexOf('/')) || '/';
        const n = p.split('/').pop();
        if (fs[par] && fs[par].children && !fs[par].children.includes(n)) {
          fs[par].children.push(n);
        }
      });
      break;
    case 'touch':
      args.forEach(f => {
        const p = resolvePath(f, cwd);
        if (!fs[p]) {
          fs[p] = { type: 'file', content: '' };
          const par = p.substring(0, p.lastIndexOf('/')) || '/';
          const n = p.split('/').pop();
          if (fs[par] && fs[par].children) fs[par].children.push(n);
        }
      });
      break;
    case 'rm':
      tprt('[simulated: removed]');
      break;
    case 'cp':
      tprt('[simulated: copied]');
      break;
    case 'mv':
      tprt('[simulated: moved]');
      break;
    case 'chmod':
      tprt('[simulated: permissions changed]');
      break;
    case 'sudo':
      tprt('[simulated: running as root]');
      break;
    case 'stat': {
      const f = args[0];
      if (!f) {
        tperr('stat: missing operand');
        break;
      }
      const p = resolvePath(f, cwd);
      const n = fs[p];
      if (!n) {
        tperr(`stat: ${f}: No such file or directory`);
        break;
      }
      const pm = n.perms || (n.type === 'dir' ? 'drwxr-xr-x' : '-rw-r--r--');
      tprt(`  File: ${p}\n  Type: ${n.type}\n  Size: ${(n.content || '').length}\nAccess: ${pm}\nModify: 2024-01-20 10:23:01`);
      break;
    }
    case 'file': {
      const f = args[0];
      if (!f) {
        tperr('file: missing operand');
        break;
      }
      const p = resolvePath(f, cwd);
      const n = fs[p];
      if (!n) {
        tperr(`file: ${f}: No such file or directory`);
        break;
      }
      let t = n.type === 'dir' ? 'directory' : 'ASCII text';
      if (p.endsWith('.sh')) t = 'Bourne-Again shell script, ASCII text executable';
      if (p.endsWith('.py')) t = 'Python script';
      if (p.endsWith('.gz')) t = 'gzip compressed data';
      if (p.endsWith('.elf') || p.includes('agent')) t = 'ELF 64-bit LSB executable';
      tprt(`${p}: ${t}`);
      break;
    }
    case 'which': {
      const b = { bash: '/bin/bash', python3: '/usr/bin/python3', find: '/usr/bin/find', grep: '/usr/bin/grep', awk: '/usr/bin/awk', sed: '/usr/bin/sed', curl: '/usr/bin/curl', base64: '/usr/bin/base64', xxd: '/usr/bin/xxd', strings: '/usr/bin/strings', rev: '/usr/bin/rev', tr: '/usr/bin/tr', nmap: '/usr/bin/nmap' };
      args.forEach(a => tpr(b[a] ? `<span class="t-out">${b[a]}</span>` : `<span class="t-err">${esc(a)}: not found</span>`));
      break;
    }
    case 'tar': {
      const f = args.find(a => a.endsWith('.gz') || a.endsWith('.tar'));
      if (!f) {
        tprt('tar: specify archive file');
        break;
      }
      const n = fs[resolvePath(f, cwd)];
      if (!n) {
        tperr(`tar: ${f}: No such file`);
        break;
      }
      tpr(`<span class="t-out">${esc(n.content || '[empty archive]')}</span>`);
      break;
    }
    case 'man':
      tprt(`man ${args[0] || '?'}: use --help or online docs`);
      break;
    case 'help':
      tpr(`<span class="t-ok">DEEBUG CTF — Terminal Commands</span>
<span class="t-out">Navigation:  ls [-la] [path]   cd [path]   pwd</span>
<span class="t-out">Files:       cat   head -n N   tail -n N   file   stat   wc</span>
<span class="t-out">Search:      find / -name "*.txt" 2>/dev/null</span>
<span class="t-out">             find / -perm -4000 2>/dev/null   (SUID)</span>
<span class="t-out">             find / -perm 777 2>/dev/null     (world-writable)</span>
<span class="t-out">             find / -newer /etc/hostname 2>/dev/null</span>
<span class="t-out">Grep:        grep "pattern" file   grep -r "pattern" /dir</span>
<span class="t-out">Text:        awk -F, '\\$2=="X"{print \\$6}' file   cut -d, -f6 file</span>
<span class="t-out">Decode:      base64 -d file   rev file   xxd -r -p file</span>
<span class="t-out">             cat file | tr 'a-zA-Z' 'n-za-mN-ZA-M'  (ROT13)</span>
<span class="t-out">             python3 -c "print(bytes.fromhex('hexstring').decode())"</span>
<span class="t-out">Network:     curl /api/v1/debug   curl -I http://localhost</span>
<span class="t-out">System:      whoami   id   ps   ss   env   history   uname -a</span>
<span class="t-out">Other:       strings file   tar xzf archive.tar.gz   clear   help</span>`);
      break;
    default:
      tperr(`bash: ${esc(cmd)}: command not found`);
  }

  autoDetect(output, solvedFlags, capturedFlags);

  return {
    output: output.join('\n'),
    newCwd: cwd,
    fsState: fs,
    capturedFlags
  };
}

function pipeCmd(raw, cwd, fs, tpr, tprt, tperr) {
  const segs = raw.split('|').map(s => s.trim());
  let content = '';
  const first = segs[0].split(/\s+/);
  const fcmd = first[0];
  const fargs = first.slice(1);

  if (fcmd === 'cat') {
    const f = fargs.find(a => !a.startsWith('-'));
    if (f) {
      const n = fs[resolvePath(f, cwd)];
      content = n ? (n.type === 'symlink' ? (fs[n.target]?.content || '') : (n.content || '')) : '';
    }
  } else if (fcmd === 'echo') {
    content = fargs.join(' ').replace(/['"]/g, '');
  } else if (fcmd === 'find') {
    const walk = (p, acc = []) => {
      const n = fs[p];
      if (!n) return acc;
      acc.push(p);
      if (n.type === 'dir' && n.children) {
        n.children.forEach(c => walk(p === '/' ? '/' + c : p + '/' + c, acc));
      }
      return acc;
    };
    const sp = fargs.find(a => !a.startsWith('-')) || cwd;
    content = walk(resolvePath(sp, cwd)).join('\n');
  }

  for (let i = 1; i < segs.length; i++) {
    const seg = segs[i].split(/\s+/);
    const scmd = seg[0];
    const sargs = seg.slice(1);

    if (scmd === 'grep') {
      const flags = sargs.filter(a => a.startsWith('-'));
      const pat = (sargs.find(a => !a.startsWith('-')) || '').replace(/['"]/g, '');
      const ci = flags.includes('-i');
      const re = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, (m) => m === '*' ? '.*' : '\\' + m), ci ? 'i' : '');
      content = content.split('\n').filter(l => re.test(l)).join('\n');
    } else if (scmd === 'tr') {
      const sets = sargs.filter(a => !a.startsWith('-'));
      if (sets.length >= 2) {
        const from = sets[0].replace(/['"]/g, '');
        const to = sets[1].replace(/['"]/g, '');
        const expand = s => {
          let r = '';
          for (let k = 0; k < s.length; k++) {
            if (s[k + 1] === '-' && s[k + 2]) {
              const a = s.charCodeAt(k), b = s.charCodeAt(k + 2);
              for (let c = a; c <= b; c++) r += String.fromCharCode(c);
              k += 2;
            } else r += s[k];
          }
          return r;
        };
        const fe = expand(from), te = expand(to);
        content = content.split('').map(c => {
          const idx = fe.indexOf(c);
          return idx > -1 ? (te[idx] || c) : c;
        }).join('');
      }
    } else if (scmd === 'base64') {
      if (sargs.includes('-d')) {
        try {
          content = Buffer.from(content.trim(), 'base64').toString('utf-8');
        } catch (e) {
          content = '[invalid base64]';
        }
      } else {
        content = Buffer.from(content).toString('base64');
      }
    } else if (scmd === 'rev') {
      content = content.split('\n').map(l => l.split('').reverse().join('')).join('\n');
    } else if (scmd === 'sort') {
      content = content.split('\n').sort().join('\n');
    } else if (scmd === 'uniq') {
      const ls = content.split('\n');
      content = ls.filter((l, idx) => l !== ls[idx - 1]).join('\n');
    } else if (scmd === 'head') {
      const n = parseInt(sargs.find(a => !a.startsWith('-'))) || 10;
      content = content.split('\n').slice(0, n).join('\n');
    } else if (scmd === 'tail') {
      const n = parseInt(sargs.find(a => !a.startsWith('-'))) || 10;
      content = content.split('\n').slice(-n).join('\n');
    } else if (scmd === 'wc') {
      const ls = content.split('\n');
      content = `${ls.length} ${content.split(/\s+/).filter(Boolean).length} ${content.length}`;
    } else if (scmd === 'awk') {
      const fi = sargs.indexOf('-F');
      const sep = fi > -1 ? sargs[fi + 1].replace(/['"]/g, '') : ' ';
      const prog = sargs.find(a => a.includes('print')) || '{print}';
      const condM = prog.match(/\$(\d+)==["']?([^"'\{]+)["']?\{/);
      const flds = (prog.match(/\$(\d+)/g) || []);
      content = content.split('\n').map(line => {
        const fs2 = line.split(sep === ' ' ? /\s+/ : new RegExp(sep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
        if (condM) {
          const ci2 = parseInt(condM[1]) - 1;
          if (fs2[ci2] !== condM[2].trim()) return null;
        }
        return flds.length ? flds.map(f => fs2[parseInt(f.slice(1)) - 1] || '').join(' ') : line;
      }).filter(l => l !== null).join('\n');
    }
  }

  if (content) {
    const out = esc(content).replace(/FLAG\{[^}]+\}/g, m => `<span class="t-flag">${m}</span>`);
    tpr(`<span class="t-out">${out}</span>`);
  }
}

function autoDetect(outputLines, solvedFlags, capturedFlags) {
  const recent = outputLines.slice(-10).join('\n');
  const matches = [...recent.matchAll(/FLAG\{[^}]+\}/g)].map(m => m[0]);
  matches.forEach(flag => {
    const c = CHALLENGES.find(x => x.flag === flag);
    if (c && !solvedFlags.includes(c.id) && !capturedFlags.includes(c.id)) {
      capturedFlags.push(c.id);
    }
  });
}

module.exports = {
  executeCommand
};
