const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('path');

const DB_PATH = path.join(__dirname, 'db.sqlite');
const db = new DatabaseSync(DB_PATH);

// Initialize DB schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_on_special INTEGER DEFAULT 0,
    start_time INTEGER NOT NULL,
    cwd TEXT DEFAULT '/home/operator',
    fs_state TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS solves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    challenge_id TEXT NOT NULL,
    solved_at INTEGER NOT NULL,
    UNIQUE(user_id, challenge_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

// Password hashing helpers
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

// Default FS template
const DEFAULT_FS = {
  '/':{ type:'dir', children:['home','root','etc','var','opt','tmp','proc','bin','usr','dev'] },
  '/home':{ type:'dir', children:['operator'] },
  '/home/operator':{ type:'dir', children:['Desktop','Documents','.bashrc','.bash_history','.flag','.encoded','.ssh','.profile'] },
  '/home/operator/.flag':{ type:'file', content:'FLAG{d0tf1l3_d1sc0v3r3d}' },
  '/home/operator/.encoded':{ type:'file', content:'RkxBR3tiNHMzNjRfZDNjMGQzcl9wcjB9' },
  '/home/operator/.bashrc':{ type:'file', content:'# /home/operator/.bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll="ls -la"\nalias grep="grep --color=auto"\n\n# Deployment secrets — migrate to vault!\nexport DEPLOY_KEY="FLAG{3xp0rt_v4r_l34k3d}"\nexport DB_PASS="n0t_th3_fl4g_3ith3r"\nexport API_SECRET="4ls0_n0t_1t_s0rry"' },
  '/home/operator/.bash_history':{ type:'file', content:'whoami\nid\nls -la\ncd /etc\ncat passwd\nsudo -l\nfind / -perm -4000 2>/dev/null\ngrep -r "password" /var/www\ncat /root/.bashrc\nhistory' },
  '/home/operator/.profile':{ type:'file', content:'# operator .profile\nif [ -f ~/.bashrc ]; then . ~/.bashrc; fi' },
  '/home/operator/.ssh':{ type:'dir', children:['id_rsa','id_rsa.pub','known_hosts'] },
  '/home/operator/.ssh/id_rsa':{ type:'file', content:'-----BEGIN RSA PRIVATE KEY-----\n[REDACTED]\n-----END RSA PRIVATE KEY-----', perms:'-rw-------' },
  '/home/operator/.ssh/id_rsa.pub':{ type:'file', content:'ssh-rsa AAAAB3NzaC1yc2EAAAA... operator@opsec' },
  '/home/operator/.ssh/known_hosts':{ type:'file', content:'10.0.0.1 ssh-rsa AAAA...\n192.168.1.1 ssh-rsa AAAB...' },
  '/home/operator/Desktop':{ type:'dir', children:['mission_brief.txt','targets.csv'] },
  '/home/operator/Desktop/mission_brief.txt':{ type:'file', content:'MISSION BRIEF — OP NIGHTFALL\n============================\nObjective: Enumerate all flags hidden across the OPSEC CTF platform.\nTotal flags: 33\nTime limit: 4 hours\n\nGood luck, operator.' },
  '/home/operator/Desktop/targets.csv':{ type:'file', content:'id,ip,hostname,status\n1,10.0.0.1,web-01,alive\n2,10.0.0.2,db-01,alive\n3,10.0.0.3,backup-01,unknown' },
  '/home/operator/Documents':{ type:'dir', children:['recon','notes.md'] },
  '/home/operator/Documents/recon':{ type:'dir', children:['nmap.txt','gobuster.txt'] },
  '/home/operator/Documents/recon/nmap.txt':{ type:'file', content:'Nmap 7.94 scan report for 10.0.0.1\nPORT    STATE SERVICE\n22/tcp  open  ssh\n80/tcp  open  http\n443/tcp open  https\n8080/tcp open  http-proxy' },
  '/home/operator/Documents/recon/gobuster.txt':{ type:'file', content:'/admin (301)\n/backup (200)\n/api (200)\n/config (403)\n/.git (200)' },
  '/home/operator/Documents/notes.md':{ type:'file', content:'# Op Notes\n- Check /proc for fake entries\n- Review crontab for suspicious scripts\n- sudoers has NOPASSWD entries\n- /opt/config has hardcoded credentials\n- Check for world-writable files' },
  '/root':{ type:'dir', children:['.bashrc','.bash_history','.flag_root','proof.txt','.vault_notes'] },
  '/root/.flag_root':{ type:'file', content:'FLAG{r00t_h0m3_0wn3d}', perms:'-rw-------' },
  '/root/proof.txt':{ type:'file', content:'You have reached /root.\nThis machine is fully compromised.\nFLAG{r00t_h0m3_0wn3d}', perms:'-rw-------' },
  '/root/.bashrc':{ type:'file', content:'# root .bashrc\nexport PATH=$PATH:/usr/local/sbin\nalias ll="ls -la"' },
  '/root/.bash_history':{ type:'file', content:'whoami\ncat /etc/shadow\npasswd operator\nfind / -writable 2>/dev/null\ncrontab -l\ncat /opt/config/secrets/master.conf' },
  '/root/.vault_notes':{ type:'file', content:'Vault address: https://vault.internal:8200\nToken: hvs.NOT_THE_FLAG\nNote: real creds in /opt/config/secrets/', perms:'-rw-------' },
  '/etc':{ type:'dir', children:['passwd','shadow','hosts','hostname','crontab','sudoers','motd','os-release','cron.d','ssh'] },
  '/etc/motd':{ type:'file', content:'\n  ██████╗ ██████╗ ███████╗███████╗ ██████╗\n  ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝\n  ██║  ██║██████╔╝███████╗█████╗  ██║\n  ██║  ██║██╔═══╝      ██║██╔══╝  ██║\n  ██████╔╝██║     ███████║███████╗╚██████╗\n\nFLAG{m0td_r34d3r}\n\nAuthorised personnel only.\n' },
  '/etc/passwd':{ type:'file', content:'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\noperator:x:1000:1000:FLAG{p4sswd_g3c0s_s3cr3t}:/home/operator:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\npostgres:x:110:118:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\nsshd:x:103:65534::/run/sshd:/usr/sbin/nologin' },
  '/etc/shadow':{ type:'file', content:'Permission denied.', perms:'-rw-r-----', owner:'root' },
  '/etc/hosts':{ type:'file', content:'127.0.0.1   localhost\n127.0.1.1   opsec-ctf\n10.0.0.1    web.internal\n10.0.0.2    db.internal\n10.0.0.3    backup.internal' },
  '/etc/hostname':{ type:'file', content:'opsec-ctf' },
  '/etc/crontab':{ type:'file', content:'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n\n# m  h  dom  mon  dow  user   command\n* *   *   *   *   root /opt/scripts/heartbeat.sh\n*/5 * *   *   *   root /opt/scripts/backup.sh\n0 2 *   *   *   root /opt/scripts/cleanup.sh\n0 0 *   *  0  root /opt/scripts/weekly.sh' },
  '/etc/sudoers':{ type:'file', content:'Defaults env_reset\nDefaults mail_badpass\n\nroot    ALL=(ALL:ALL) ALL\n\n# Operator allowed commands\noperator ALL=(ALL) NOPASSWD: /usr/bin/find\noperator ALL=(ALL) NOPASSWD: /opt/scripts/privcheck.sh\n\n%sudo   ALL=(ALL:ALL) ALL', perms:'-r--r-----' },
  '/etc/os-release':{ type:'file', content:'PRETTY_NAME="Kali GNU/Linux Rolling"\nNAME="Kali GNU/Linux"\nID=kali\nID_LIKE=debian\nVERSION="2024.2"\nHOME_URL="https://www.kali.org/"' },
  '/etc/ssh':{ type:'dir', children:['sshd_config'] },
  '/etc/ssh/sshd_config':{ type:'file', content:'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication yes' },
  '/etc/cron.d':{ type:'dir', children:['apt','php8'] },
  '/var':{ type:'dir', children:['log','www','backups','tmp','mail'] },
  '/var/log':{ type:'dir', children:['syslog','auth.log','app.log','kern.log','dpkg.log','apache2'] },
  '/var/log/syslog':{ type:'file', content:(() => {
    const lines=[];
    for(let i=1;i<900;i++) lines.push(`Jan 20 ${String(Math.floor(i/60)%24).padStart(2,'0')}:${String(i%60).padStart(2,'0')}:${String(i%60).padStart(2,'0')} opsec-ctf systemd[1]: heartbeat check #${i}`);
    lines.push('Jan 20 23:59:59 opsec-ctf kernel: [9999.999] FLAG{t41l_3nd_0f_l0g}');
    return lines.join('\n');
  })() },
  '/var/log/auth.log':{ type:'file', content:(() => {
    const lines=['Jan 20 08:00:00 opsec-ctf sshd[100]: Server listening on 0.0.0.0 port 22'];
    for(let i=0;i<60;i++) lines.push(`Jan 20 08:${String(i).padStart(2,'0')}:00 opsec-ctf sshd[${900+i}]: Accepted password for operator from 10.0.0.${i+1} port ${40000+i}`);
    lines.push('Jan 20 09:15:44 opsec-ctf sudo[1337]: OPERATION BLACKOUT — FLAG{4uth_l0g_r34d3r} — initiated by root');
    for(let i=0;i<40;i++) lines.push(`Jan 20 10:${String(i).padStart(2,'0')}:00 opsec-ctf su[${2000+i}]: FAILED su for root by operator`);
    return lines.join('\n');
  })() },
  '/var/log/app.log':{ type:'file', content:(() => {
    const levels=['DEBUG','INFO','WARN','ERROR'];
    const lines=[];
    for(let i=1;i<=500;i++) lines.push(`[${levels[i%4]}] req_${String(i).padStart(5,'0')} user=agent${i%20} status=${i%7===0?500:200} ms=${10+i%80}`);
    lines.push('[INFO] req_00501 TROPHY_EVENT token=FLAG{gr3p_1s_3ss3nt14l} status=200 ms=12');
    for(let i=502;i<=1000;i++) lines.push(`[${levels[i%4]}] req_${String(i).padStart(5,'0')} user=agent${i%20} status=${i%9===0?403:200} ms=${10+i%80}`);
    return lines.join('\n');
  })() },
  '/var/log/apache2':{ type:'dir', children:['access.log','error.log'] },
  '/var/log/apache2/access.log':{ type:'file', content:'10.0.0.1 - - [20/Jan/2024:08:00:01] "GET / HTTP/1.1" 200 11173\n10.0.0.1 - - [20/Jan/2024:08:00:02] "GET /admin HTTP/1.1" 301 0\n10.0.0.1 - admin [20/Jan/2024:08:01:00] "POST /login HTTP/1.1" 200 0' },
  '/var/www':{ type:'dir', children:['html'] },
  '/var/www/html':{ type:'dir', children:['index.html','config.php','.env','wp-config.php'] },
  '/var/www/html/config.php':{ type:'file', content:'<?php\n$db_host="localhost";\n$db_user="webapp";\n$db_pass="W3b4pp_Sup3r_S3cur3!";\n$db_name="opsec_db";\n$api_secret="NOT_THE_FLAG_HERE";\n?>' },
  '/var/www/html/.env':{ type:'file', content:'APP_ENV=production\nAPP_KEY=base64:NOT_REAL\nDB_HOST=localhost\nDB_PASSWORD=DBP4ss_2024!\nMAIL_PASSWORD=m41l_p4ss\nAWS_SECRET=NOT_REAL' },
  '/var/backups':{ type:'dir', children:['etc_20240120.tar.gz','shadow.bak'] },
  '/var/backups/shadow.bak':{ type:'file', content:'root:$6$salt$h4sh3dp4ss\noperator:$6$salt$h4sh3dp4ss2', perms:'-rw-------', owner:'root' },
  '/opt':{ type:'dir', children:['scripts','data','encoded','fragments','config','bin','links','maze','final','writable'] },
  '/opt/scripts':{ type:'dir', children:['heartbeat.sh','backup.sh','cleanup.sh','privcheck.sh','deploy.sh','weekly.sh'] },
  '/opt/scripts/heartbeat.sh':{ type:'file', content:'#!/bin/bash\n# Cron: runs every minute as root\n# Verification token: FLAG{cr0n_scr1pt_3xp0s3d}\ndate >> /var/log/heartbeat.log\necho "alive" > /tmp/heartbeat', perms:'-rwxr-xr-x', owner:'root' },
  '/opt/scripts/backup.sh':{ type:'file', content:'#!/bin/bash\ntar czf /var/backups/home_$(date +%Y%m%d).tar.gz /home/operator 2>/dev/null\necho "Backup complete"', perms:'-rwxr-xr-x', owner:'root' },
  '/opt/scripts/cleanup.sh':{ type:'file', content:'#!/bin/bash\nfind /tmp -name "*.tmp" -mtime +1 -delete\necho "Cleaned"', perms:'-rwxr-xr-x', owner:'root' },
  '/opt/scripts/privcheck.sh':{ type:'file', content:'#!/bin/bash\n# Allowed in sudoers: operator can run as root\necho "[*] Checking system vectors..."\nfind / -perm -4000 2>/dev/null\necho ""\necho "FLAG{sud03rs_pr1v3sc_p4th}"\necho "[*] Review /etc/sudoers for details"', perms:'-rwxr-xr-x', owner:'root' },
  '/opt/scripts/deploy.sh':{ type:'file', content:'#!/bin/bash\n# Production deployment script\nVERSION="3.1.0"\necho "Deploying v$VERSION..."\n\ncat > /tmp/deploy.conf << HEREDOC\napp: opsec-ctf\nversion: 3.1.0\nflag: FLAG{h3r3d0c_1ns1d3}\nenv: production\nHEREDOC\n\necho "Done. Config at /tmp/deploy.conf"', perms:'-rwxr-xr-x' },
  '/opt/scripts/weekly.sh':{ type:'file', content:'#!/bin/bash\necho "Weekly report" > /tmp/weekly.txt\ndf -h >> /tmp/weekly.txt\nwho >> /tmp/weekly.txt', perms:'-rwxr-xr-x', owner:'root' },
  '/opt/data':{ type:'dir', children:['ops.csv','agents.db','inventory.json'] },
  '/opt/data/ops.csv':{ type:'file', content:'ID,CODENAME,STATUS,REGION,CLEARANCE,TOKEN\n001,BLUEBIRD,ACTIVE,EU,TOP_SECRET,n0t_1t_s0rry\n002,IRONCLAD,RETIRED,APAC,SECRET,4ls0_n0p3\n003,SPECTRE,ACTIVE,AMER,TOP_SECRET,FLAG{4wk_csv_3xtr4ct10n}\n004,PHANTOM,INACTIVE,MENA,SECRET,wr0ng_4g41n\n005,CIPHER,ACTIVE,EU,TOP_SECRET,n3v3r_m1nd' },
  '/opt/data/agents.db':{ type:'file', content:'id|handle|status|clearance\n1|ghost_0x|ACTIVE|L5\n2|n0x3r|ACTIVE|L4\n3|cipher7|RETIRED|L3' },
  '/opt/encoded':{ type:'dir', children:['mirror.txt','cipher.txt','hex.txt'] },
  '/opt/encoded/mirror.txt':{ type:'file', content:'}d3sr3v3r_r0rr1m{GALF' },
  '/opt/encoded/cipher.txt':{ type:'file', content:'SYNT{e0g13_q3p0q3q_4t41a}' },
  '/opt/encoded/hex.txt':{ type:'file', content:'464c41477b6833785f6d4173743372217d\n\n# Decode with: python3 -c "print(bytes.fromhex(\'464c41477b6833785f6d4173743372217d\').decode())"' },
  '/opt/fragments':{ type:'dir', children:['alpha','beta','gamma','decoy'] },
  '/opt/fragments/alpha':{ type:'file', content:'FLAG{fr4gm3nts' },
  '/opt/fragments/beta':{ type:'file', content:'_r3un1t3d' },
  '/opt/fragments/gamma':{ type:'file', content:'}' },
  '/opt/fragments/decoy':{ type:'file', content:'Not a fragment. A distraction.' },
  '/opt/config':{ type:'dir', children:['app.conf','db.conf','secrets'] },
  '/opt/config/app.conf':{ type:'file', content:'[app]\nhost=0.0.0.0\nport=8080\nlog_level=INFO\ndebug=false' },
  '/opt/config/db.conf':{ type:'file', content:'[database]\nhost=localhost\nport=5432\nname=opsecdb\nuser=opsec_app\npassword=DB_Sup3r_S3cur3_2024' },
  '/opt/config/secrets':{ type:'dir', children:['api_keys.conf','master.conf'] },
  '/opt/config/secrets/api_keys.conf':{ type:'file', content:'[keys]\nstripe=sk_live_NOT_REAL\nsendgrid=SG.NOT_REAL\n# No flags here, keep looking' },
  '/opt/config/secrets/master.conf':{ type:'file', content:'[master]\nsystem_token=SYS_T0K3N_NOT_FLAG\n\n# MASTER_KEY = FLAG{r3curs1v3_gr3p_m4st3r}\n# ^ found it? good job.' },
  '/opt/bin':{ type:'dir', children:['agent.elf','scanner','patcher'] },
  '/opt/bin/agent.elf':{ type:'file', content:'\x00ELF\x02\x01garbage_data_XXXXXX\nBBBBBBBBBBBBBB\nCCCCCCCCCCCC\x00\x01\x02FLAG{str1ngs_0n_b1n4ry}\x00\x00\x00\nmore_junk_DDDDDDDDDD\n\xff\xfe\xfd\x00' },
  '/opt/bin/scanner':{ type:'file', content:'[ELF binary — not human readable]\nUse strings to extract text.', perms:'-rwxr-xr-x' },
  '/opt/links':{ type:'dir', children:['link_docs','link_etc','link_shadow','secret_link'] },
  '/opt/links/link_docs':{ type:'symlink', target:'/home/operator/Documents/notes.md' },
  '/opt/links/link_etc':{ type:'symlink', target:'/etc/hostname' },
  '/opt/links/link_shadow':{ type:'symlink', target:'/etc/shadow' },
  '/opt/links/secret_link':{ type:'symlink', target:'/opt/.hidden_vault/token.txt' },
  '/opt/.hidden_vault':{ type:'dir', children:['token.txt'] },
  '/opt/.hidden_vault/token.txt':{ type:'file', content:'FLAG{syml1nk_targ3t_f0und}' },
  '/opt/writable':{ type:'dir', children:['community.txt','shared.log'] },
  '/opt/writable/community.txt':{ type:'file', content:'Community notes:\n\nFLAG{777_p3rm_d4ng3r0us}\n\nAdd your notes here.', perms:'-rwxrwxrwx' },
  '/opt/writable/shared.log':{ type:'file', content:'[log entries]\n2024-01-20 10:00:00 operator login\n2024-01-20 10:05:12 operator ran find', perms:'-rw-rw-rw-' },
  '/opt/final':{ type:'dir', children:['shard_1','shard_2','shard_3','README'] },
  '/opt/final/README':{ type:'file', content:'FINAL CHALLENGE\n===============\nThree shards. Each ROT13 encoded.\nDecode each, concatenate in order.\nshard_1 + shard_2 + shard_3 = final flag.\nGood luck.' },
  '/opt/final/shard_1':{ type:'file', content:'SYNT{s1a4y' },
  '/opt/final/shard_2':{ type:'file', content:'_q3pelcg10a' },
  '/opt/final/shard_3':{ type:'file', content:'_p0zcyr3gr}' },
  '/opt/maze':{ type:'dir', children:['l1'] },
  '/opt/maze/l1':{ type:'dir', children:['l2','decoy.txt'] },
  '/opt/maze/l1/decoy.txt':{ type:'file', content:'Not here.' },
  '/opt/maze/l1/l2':{ type:'dir', children:['l3'] },
  '/opt/maze/l1/l2/l3':{ type:'dir', children:['l4','false.txt'] },
  '/opt/maze/l1/l2/l3/false.txt':{ type:'file', content:'Nope.' },
  '/opt/maze/l1/l2/l3/l4':{ type:'dir', children:['l5'] },
  '/opt/maze/l1/l2/l3/l4/l5':{ type:'dir', children:['l6','red_herring.txt'] },
  '/opt/maze/l1/l2/l3/l4/l5/red_herring.txt':{ type:'file', content:'Almost.' },
  '/opt/maze/l1/l2/l3/l4/l5/l6':{ type:'dir', children:['l7'] },
  '/opt/maze/l1/l2/l3/l4/l5/l6/l7':{ type:'dir', children:['l8'] },
  '/opt/maze/l1/l2/l3/l4/l5/l6/l7/l8':{ type:'dir', children:['l9'] },
  '/opt/maze/l1/l2/l3/l4/l5/l6/l7/l8/l9':{ type:'dir', children:['.maze_flag'] },
  '/opt/maze/l1/l2/l3/l4/l5/l6/l7/l8/l9/.maze_flag':{ type:'file', content:'FLAG{m4z3_w4lk3r_9_l3v3ls}' },
  '/proc':{ type:'dir', children:['version','cpuinfo','meminfo','secret','net'] },
  '/proc/version':{ type:'file', content:'Linux version 6.1.0-kali9-amd64 (devel@kali.org) (gcc 12.2.0) #1 SMP PREEMPT Debian 6.1.27-1' },
  '/proc/cpuinfo':{ type:'file', content:'processor\t: 0\nmodel name\t: Intel Core i7-13700H @ 2.40GHz\ncpu MHz\t\t: 2400.000' },
  '/proc/meminfo':{ type:'file', content:'MemTotal:\t16384000 kB\nMemFree:\t  8192000 kB\nMemAvailable:\t 10240000 kB' },
  '/proc/secret':{ type:'file', content:'FLAG{pr0c_f4k3_f1l3}' },
  '/proc/net':{ type:'dir', children:['tcp','udp'] },
  '/proc/net/tcp':{ type:'file', content:'sl  local_address rem_address  st\n 0: 00000000:0016 00000000:0000 0A\n 1: 0100007F:1F40 00000000:0000 0A' },
  '/tmp':{ type:'dir', children:['heartbeat','session.tmp','xf3r_9k2.dat','deploy.conf'] },
  '/tmp/xf3r_9k2.dat':{ type:'file', content:'temp evidence file\nFLAG hidden: not here, keep looking' },
  '/tmp/session.tmp':{ type:'file', content:'session_id=8f2c4a1d\nuser=operator\nexpires=1705363200' },
  '/bin':{ type:'dir', children:['bash','sh','ls','cat','find','grep','awk','sed','cut','rev','base64','tr','strings','wc','echo','ps','ping','date','hostname','id','whoami'] },
  '/usr':{ type:'dir', children:['bin','share','local'] },
  '/usr/bin':{ type:'dir', children:['python3','nmap','curl','wget','nc','xxd','ssh','sudo','vim','nano','less','more','file','stat','diff','sort','uniq','head','tail','chmod','chown','chattr','lsattr','strace','ltrace'] },
  '/usr/share':{ type:'dir', children:['wordlists','doc'] },
  '/usr/share/wordlists':{ type:'dir', children:['rockyou.txt.gz','dirbuster'] },
  '/dev':{ type:'dir', children:['null','zero','random','urandom','sda','tty'] },
};

// Add SUID path with flag
DEFAULT_FS['/usr/bin/FLAG{su1d_b1n4ry_f0und}'] = { type:'file', content:'[SUID binary — suspicious name]', perms:'-rwsr-xr-x' };
DEFAULT_FS['/usr/bin'].children.push('FLAG{su1d_b1n4ry_f0und}');

// Newest file
DEFAULT_FS['/var/log/latest_evidence.log'] = { type:'file', content:'[CRITICAL] Anomaly detected at 23:59:59\nFLAG{n3w3st_f1l3_w1ns}\nAction required.' };
DEFAULT_FS['/var/log'].children.push('latest_evidence.log');

// Seed default users if table is empty
function seed() {
  const checkStmt = db.prepare('SELECT COUNT(*) as count FROM users');
  const result = checkStmt.get();
  if (result.count === 0) {
    const insertUser = db.prepare(`
      INSERT INTO users (username, password_hash, role, is_on_special, start_time, fs_state)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    // Seed operator
    insertUser.run(
      'operator',
      hashPassword('letmein'),
      'player',
      0,
      Date.now(),
      JSON.stringify(DEFAULT_FS)
    );

    // Seed admin
    insertUser.run(
      'admin',
      hashPassword('4dm1n_0psec'),
      'super_admin',
      0,
      Date.now(),
      JSON.stringify(DEFAULT_FS)
    );
    console.log('Database seeded with default accounts.');
  }
}

seed();

module.exports = {
  db,
  hashPassword,
  verifyPassword,
  DEFAULT_FS
};
