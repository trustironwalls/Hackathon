const CHALLENGES = [
  // ── WEB RECON (flags hidden in UI pages) ─────────────────
  {id:'w1',cat:'Web Recon',name:'View Source',diff:'easy',pts:50,
   desc:'Every hacker starts by reading the page source. Something valuable is hidden in a comment on the login page.',
   hint:'Open the login page → right-click → View Page Source. Search for FLAG{',
   flag:'FLAG{v13w_s0urc3_f1rst_alw4ys}'},

  {id:'w2',cat:'Web Recon',name:'Inspect Element',diff:'easy',pts:75,
   desc:'The scoreboard chart element has a secret attribute. Browser DevTools → Elements tab.',
   hint:'Open the Scoreboard page. Press F12 → Elements → find the <canvas> tag → look at its attributes.',
   flag:'FLAG{1nsp3ct_3l3m3nt_pr0}'},

  {id:'w3',cat:'Web Recon',name:'Dashboard Source',diff:'easy',pts:75,
   desc:'The dashboard HTML source contains a hidden comment. You know what to do.',
   hint:'On the Dashboard page: View Page Source (Ctrl+U) and search for FLAG{',
   flag:'FLAG{d4shb04rd_s0urc3_hunt3r}'},

  {id:'w4',cat:'Web Recon',name:'Cookie Monster',diff:'med',pts:125,
   desc:'The platform sets a session cookie with a suspicious value. Check your browser cookies.',
   hint:'F12 → Application (Chrome) or Storage (Firefox) → Cookies → find the session cookie value.',
   flag:'FLAG{c00k13_m0nst3r_f0und}'},

  {id:'w5',cat:'Web Recon',name:'Local Storage',diff:'med',pts:125,
   desc:'Something was stored in localStorage that should not be there. Check your browser storage.',
   hint:'F12 → Application → Local Storage → look at all keys, not just the obvious ones.',
   flag:'FLAG{l0c4l_st0r4g3_l34k}'},

  {id:'w6',cat:'Web Recon',name:'robots.txt',diff:'easy',pts:75,
   desc:'The platform has a robots.txt. It lists paths that should not be indexed — including one with a flag.',
   hint:'Imagine the URL: /robots.txt — what would it contain? The flag is in the Disallow comments.',
   flag:'FLAG{r0b0ts_txt_3xp0s3d}'},

  {id:'w7',cat:'Web Recon',name:'API Endpoint',diff:'hard',pts:200,
   desc:'There is a hidden API debug endpoint. Call /api/v1/debug in the terminal with curl to retrieve the flag.',
   hint:'In the terminal type: curl /api/v1/debug — the response JSON contains a flag field.',
   flag:'FLAG{4p1_d3bug_3ndp01nt}'},

  {id:'w8',cat:'Web Recon',name:'HTTP Headers',diff:'hard',pts:200,
   desc:'The server leaks a flag in a custom HTTP response header. Use curl -I to see response headers.',
   hint:'In the terminal: curl -I http://localhost — look for an X-Flag header in the response.',
   flag:'FLAG{h3ad3r_1nj3ct10n}'},

  // ── LINUX FILESYSTEM ─────────────────────────────────────
  {id:'l1',cat:'Linux: Basics',name:'The Dotfile',diff:'easy',pts:50,
   desc:'A hidden file in /home/operator contains a flag. Hidden files start with a dot.',
   hint:'cd /home/operator && ls -la — look for a dotfile',
   flag:'FLAG{d0tf1l3_d1sc0v3r3d}'},

  {id:'l2',cat:'Linux: Basics',name:'MOTD Message',diff:'easy',pts:50,
   desc:'The message of the day (/etc/motd) was customised by the sysadmin and hides a flag.',
   hint:'cat /etc/motd',
   flag:'FLAG{m0td_r34d3r}'},

  {id:'l3',cat:'Linux: Basics',name:'Passwd Comment',diff:'easy',pts:75,
   desc:'The GECOS field (field 5) of one entry in /etc/passwd contains a flag instead of a real name.',
   hint:'cat /etc/passwd — look at the 5th colon-separated field for each user line.',
   flag:'FLAG{p4sswd_g3c0s_s3cr3t}'},

  {id:'l4',cat:'Linux: Basics',name:'End of Log',diff:'easy',pts:75,
   desc:'/var/log/syslog has 900+ lines. The flag is on the very last line.',
   hint:'tail -n 1 /var/log/syslog',
   flag:'FLAG{t41l_3nd_0f_l0g}'},

  {id:'l5',cat:'Linux: Basics',name:'Root Home',diff:'easy',pts:100,
   desc:'Navigate to /root and list all files, including hidden ones. The flag is in a hidden file.',
   hint:'ls -la /root — look for a dotfile',
   flag:'FLAG{r00t_h0m3_0wn3d}'},

  {id:'l6',cat:'Linux: Text',name:'Base64 Decode',diff:'med',pts:125,
   desc:'cat /home/operator/.encoded — the file contains base64 data. Decode it.',
   hint:'cat /home/operator/.encoded | base64 -d',
   flag:'FLAG{b4s364_d3c0d3r_pr0}'},

  {id:'l7',cat:'Linux: Text',name:'Grep the Log',diff:'med',pts:125,
   desc:'1000 lines in /var/log/app.log. One line contains the word TROPHY. Use grep.',
   hint:'grep "TROPHY" /var/log/app.log',
   flag:'FLAG{gr3p_1s_3ss3nt14l}'},

  {id:'l8',cat:'Linux: Text',name:'AWK Fields',diff:'med',pts:150,
   desc:'/opt/data/ops.csv is a CSV. Extract field 6 from the row where field 2 equals SPECTRE.',
   hint:"awk -F, '\\$2==\"SPECTRE\"{print \\$6}' /opt/data/ops.csv",
   flag:'FLAG{4wk_csv_3xtr4ct10n}'},

  {id:'l9',cat:'Linux: Text',name:'Reversed String',diff:'med',pts:125,
   desc:'/opt/encoded/mirror.txt contains the flag written backwards. Use rev to flip it.',
   hint:'rev /opt/encoded/mirror.txt',
   flag:'FLAG{m1rr0r_r3v3rs3d}'},

  {id:'l10',cat:'Linux: Text',name:'ROT13 Cipher',diff:'med',pts:150,
   desc:'/opt/encoded/cipher.txt is ROT13 encoded. Decode it with tr.',
   hint:"cat /opt/encoded/cipher.txt | tr 'a-zA-Z' 'n-za-mN-ZA-M'",
   flag:'FLAG{r0t13_d3c0d3d_4g41n}'},

  {id:'l11',cat:'Linux: Text',name:'Three Fragments',diff:'med',pts:175,
   desc:'The flag is split across /opt/fragments/alpha, beta, gamma. Concatenate them in order.',
   hint:'cat /opt/fragments/alpha /opt/fragments/beta /opt/fragments/gamma',
   flag:'FLAG{fr4gm3nts_r3un1t3d}'},

  {id:'l12',cat:'Linux: Text',name:'Hex Decode',diff:'hard',pts:200,
   desc:'/opt/encoded/hex.txt contains a hex string. Decode it with xxd or python3.',
   hint:"python3 -c \"print(bytes.fromhex('464c41477b6833785f6d4173743372217d').decode())\"",
   flag:'FLAG{h3x_mAst3r!}'},

  {id:'l13',cat:'Linux: Advanced',name:'Deep Directory',diff:'hard',pts:200,
   desc:'A flag is hidden 9 directories deep inside /opt/maze. Use find or keep cd-ing.',
   hint:'find /opt/maze -name "*.flag" 2>/dev/null',
   flag:'FLAG{m4z3_w4lk3r_9_l3v3ls}'},

  {id:'l14',cat:'Linux: Advanced',name:'Cron Script',diff:'hard',pts:200,
   desc:'A cron job runs every minute. Find it in /etc/crontab and read the script it calls.',
   hint:'cat /etc/crontab — find the script path — cat that script',
   flag:'FLAG{cr0n_scr1pt_3xp0s3d}'},

  {id:'l15',cat:'Linux: Advanced',name:'SUID Binary',diff:'hard',pts:225,
   desc:'Find all SUID binaries on the system. One path is suspiciously named.',
   hint:'find / -perm -4000 2>/dev/null — one path contains FLAG{',
   flag:'FLAG{su1d_b1n4ry_f0und}'},

  {id:'l16',cat:'Linux: Advanced',name:'Environment Leak',diff:'med',pts:150,
   desc:'A secret is exported inside /home/operator/.bashrc as an environment variable.',
   hint:'cat /home/operator/.bashrc — look for export statements',
   flag:'FLAG{3xp0rt_v4r_l34k3d}'},

  {id:'l17',cat:'Linux: Advanced',name:'World Writable',diff:'hard',pts:225,
   desc:'A world-writable file (chmod 777) contains a flag. Use find with -perm 777.',
   hint:'find / -perm -0002 -type f 2>/dev/null',
   flag:'FLAG{777_p3rm_d4ng3r0us}'},

  {id:'l18',cat:'Linux: Advanced',name:'Strings in Binary',diff:'hard',pts:225,
   desc:'/opt/bin/agent.elf looks like a binary. Use strings or grep to extract readable text.',
   hint:'strings /opt/bin/agent.elf | grep FLAG',
   flag:'FLAG{str1ngs_0n_b1n4ry}'},

  {id:'l19',cat:'Linux: Advanced',name:'Auth Log',diff:'hard',pts:200,
   desc:'grep /var/log/auth.log for lines containing OPERATION — a flag is embedded.',
   hint:'grep "OPERATION" /var/log/auth.log',
   flag:'FLAG{4uth_l0g_r34d3r}'},

  {id:'l20',cat:'Linux: Advanced',name:'Symlink Target',diff:'hard',pts:225,
   desc:'/opt/links/ contains symlinks. One points to an unusual target that holds a flag.',
   hint:'ls -la /opt/links/ — follow the symlink that points outside /opt',
   flag:'FLAG{syml1nk_targ3t_f0und}'},

  {id:'l21',cat:'Linux: Expert',name:'/proc Secrets',diff:'expert',pts:300,
   desc:'A fake /proc entry contains a flag. Not all /proc files are kernel-generated.',
   hint:'ls /proc && cat /proc/secret',
   flag:'FLAG{pr0c_f4k3_f1l3}'},

  {id:'l22',cat:'Linux: Expert',name:'Heredoc Flag',diff:'expert',pts:300,
   desc:'/opt/scripts/deploy.sh uses a heredoc. Read every line — the flag is inside the heredoc block.',
   hint:'cat /opt/scripts/deploy.sh — look for << EOF blocks',
   flag:'FLAG{h3r3d0c_1ns1d3}'},

  {id:'l23',cat:'Linux: Expert',name:'Recursive Config',diff:'expert',pts:325,
   desc:'grep -r through /opt/config for the string MASTER_KEY. The flag is its value.',
   hint:'grep -r "MASTER_KEY" /opt/config 2>/dev/null',
   flag:'FLAG{r3curs1v3_gr3p_m4st3r}'},

  {id:'l24',cat:'Linux: Expert',name:'sudoers Vector',diff:'expert',pts:325,
   desc:'/etc/sudoers reveals a NOPASSWD command. Read that script — it contains a flag.',
   hint:'cat /etc/sudoers — find the NOPASSWD path — cat that file',
   flag:'FLAG{sud03rs_pr1v3sc_p4th}'},

  {id:'l25',cat:'Linux: Expert',name:'Newest File',diff:'expert',pts:300,
   desc:'Find the most recently modified file under /var using find -newer. It holds a flag.',
   hint:'find /var -type f -newer /etc/hostname 2>/dev/null',
   flag:'FLAG{n3w3st_f1l3_w1ns}'},

  // ── FINAL ──────────────────────────────────────────────
  {id:'f1',cat:'Final Boss',name:'THE FINAL DECRYPTION',diff:'expert',pts:500,
   desc:'Three files: /opt/final/shard_1, shard_2, shard_3. Each is ROT13 encoded. Decode each, then concatenate in order to get the flag.',
   hint:"cat /opt/final/shard_1 | tr 'a-zA-Z' 'n-za-mN-ZA-M' — repeat for shard_2 and shard_3 — combine",
   flag:'FLAG{f1n4l_d3crypt10n_c0mpl3t3}'},
];

module.exports = CHALLENGES;
