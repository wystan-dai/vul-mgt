#!/bin/bash
# =====================================================================
# hunt-masquerade.sh —— Linux 伪装木马快速排查（只读，不修改系统）
# 适用：CentOS / RHEL 7–9（依赖 rpm）。以 root 运行。
# 目标：找出伪装成 packagekit、kworker、sshd 等系统进程名的恶意程序、
#       隧道/C2 外连、持久化项和被替换的系统命令。
# 用法：bash hunt-masquerade.sh      # 报告写入 /root/hunt_<主机名>_<时间>.txt
# =====================================================================
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行"; exit 1; }

SINCE="${SINCE:-2026-10-16 00:00}"   # 关注此时间之后的变化，可用环境变量覆盖
OUT="/root/hunt_$(hostname)_$(date +%m%d%H%M).txt"
exec > >(tee "$OUT") 2>&1

# 已知合法的第三方安装目录（不属于 RPM 包，但属于正常组件）。按实际情况增删。
KNOWN_PREFIX='^(/usr/local/php/|/usr/local/nginx/|/usr/local/datakit/|/usr/local/hostguard/|/usr/local/uniagent/|/opt/oss/|/usr/local/telescope/)'
# 内网与本机地址（外连检查时排除）
PRIV='^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.|::1|\[::1\]|\[::ffff:127)'

sec(){ echo; echo "=================== $* ==================="; }
owned(){ rpm -qf "$1" >/dev/null 2>&1; }

echo "主机: $(hostname)  时间: $(date '+%F %T %Z')  关注起点: $SINCE"

# ---------------------------------------------------------------------
sec "0. 先确认排查工具本身没有被替换（被替换则后续结果不可信）"
rpm -V procps-ng iproute net-tools coreutils findutils util-linux openssh-server systemd rpm 2>/dev/null \
  | grep -E '^..5' || echo "OK：ps/ss/netstat/ls/find/sshd/systemctl/rpm 的哈希与安装包一致"
if [ -s /etc/ld.so.preload ]; then
  echo "!! 高危：/etc/ld.so.preload 非空（用户态 rootkit 常用手法）："; cat /etc/ld.so.preload
else
  echo "OK：/etc/ld.so.preload 不存在或为空"
fi
command -v lsmod >/dev/null && lsmod | awk 'NR>1{print $1}' | while read -r m; do
  f=$(modinfo -n "$m" 2>/dev/null)
  [ -n "$f" ] && [ -e "$f" ] && ! owned "$f" && echo "!! 不属于任何 RPM 包的内核模块：$m ($f)"
done

# ---------------------------------------------------------------------
sec "1. 运行中进程：已删除 / 可疑路径 / 不属于 RPM / 伪装内核线程 / 名称与文件不符"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  [ -n "$exe" ] || continue
  comm=$(cat "$p/comm" 2>/dev/null)
  cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-160)
  user=$(stat -c %U "$p" 2>/dev/null)
  real=${exe% (deleted)}
  flag=""
  [[ "$exe" == *" (deleted)" ]] && flag+=" 文件已删除"
  [[ "$exe" == /memfd:* ]] && flag+=" 无文件落地(memfd)"
  case "$real" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*|/root/*|/opt/www/*|*/.*) flag+=" 可疑路径";;
  esac
  [[ "$cmd" == \[* ]] && flag+=" 伪装内核线程"
  if [ -e "$real" ] && ! owned "$real" && ! [[ "$real" =~ $KNOWN_PREFIX ]]; then flag+=" 不属于RPM"; fi
  base=$(basename "$real")
  case "$base" in bash|sh|dash|python*|perl*|php*|java|node|ruby*|busybox) ;;
    *) [ "${base:0:15}" != "$comm" ] && [ -n "$comm" ] && flag+=" 进程名≠文件名(${comm}≠${base})";;
  esac
  [ -n "$flag" ] && printf 'PID=%s 用户=%s 文件=%s\n   标记:%s\n   命令行: %s\n' "$pid" "$user" "$exe" "$flag" "$cmd"
done

# ---------------------------------------------------------------------
sec "2. 常被冒充的系统进程名：逐个核对真实文件路径与 RPM 归属"
for n in packagekitd packagekit kworker kthreadd ksoftirqd kdevtmpfs kswapd0 watchdog \
         sshd crond rsyslogd systemd-journald systemd-logind dbus-daemon polkitd tuned \
         auditd udevd irqbalance chronyd NetworkManager gssproxy agetty atd; do
  for pid in $(pgrep -f -- "$n" 2>/dev/null | grep -vxE "$$|$PPID"); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    [ -z "$exe" ] && continue                         # 真正的内核线程没有 exe
    real=${exe% (deleted)}
    if pkg=$(rpm -qf "$real" 2>/dev/null); then mark="ok"; else mark="!! 可疑"; pkg="无归属"; fi
    echo "$mark  名称匹配=$n PID=$pid 文件=$exe 软件包=$pkg"
  done
done | sort -u | grep -v '^ok' || echo "OK：未发现冒充系统进程名的程序"
echo "--- PackageKit 专项 ---"
rpm -q PackageKit 2>/dev/null || echo "本机未安装 PackageKit：凡是名为 packagekit* 的进程都应视为恶意"
pgrep -a -i packagekit || echo "当前无 packagekit 相关进程"
find / -xdev -iname "*packagekit*" -type f -perm /111 2>/dev/null | while read -r f; do owned "$f" || echo "!! 不属于RPM的 packagekit 文件：$f"; done

# ---------------------------------------------------------------------
sec "3. 隐藏进程（/proc 中存在但 ps 看不到，提示 rootkit）"
ps -eo pid= | tr -d ' ' | sort > /tmp/.h_ps.$$
ls /proc | grep -E '^[0-9]+$' | sort > /tmp/.h_proc.$$
for pid in $(comm -13 /tmp/.h_ps.$$ /tmp/.h_proc.$$); do
  [ -d "/proc/$pid" ] && ! ps -p "$pid" >/dev/null 2>&1 && \
    echo "!! 隐藏进程 PID=$pid exe=$(readlink /proc/$pid/exe 2>/dev/null) cmd=$(tr '\0' ' ' </proc/$pid/cmdline 2>/dev/null)"
done
rm -f /tmp/.h_ps.$$ /tmp/.h_proc.$$
echo "（短暂进程可能造成误报，出现结果请复查）"

# ---------------------------------------------------------------------
sec "4. 外连：连向公网地址的已建立连接（隧道 / C2 重点看这里）"
ss -tnpH state established 2>/dev/null | while read -r _ _ local peer proc; do
  ip=${peer%:*}; ip=${ip#[}; ip=${ip%]}
  [[ "$ip" =~ $PRIV ]] && continue
  echo "$local -> $peer  $proc"
done | sort | uniq -c | sort -rn
echo "--- 监听端口中不属于 RPM 的程序 ---"
ss -tulnpH 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | while read -r pid; do
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null); real=${exe% (deleted)}
  [ -n "$real" ] && ! owned "$real" && ! [[ "$real" =~ $KNOWN_PREFIX ]] && \
    echo "!! PID=$pid $exe 监听: $(ss -tulnpH | grep "pid=$pid," | awk '{print $1, $5}' | tr '\n' ' ')"
done

# ---------------------------------------------------------------------
sec "5. 持久化"
echo "--- 不属于 RPM 的 systemd 单元 ---"
for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service /usr/lib/systemd/system/*.service \
         /etc/systemd/system/*.timer /usr/lib/systemd/system/*.timer; do
  [ -f "$f" ] && [ ! -L "$f" ] && ! owned "$f" && echo "$f  -> $(grep -m1 '^ExecStart' "$f")"
done
echo "--- 计划任务 ---"
for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)'); [ -n "$c" ] && echo "[$u] $c"; done
grep -rvhE '^\s*(#|$|SHELL|PATH|MAILTO|HOME)' /etc/crontab /etc/cron.d/ 2>/dev/null
find /etc/cron* /var/spool/cron -type f -newermt "$SINCE" -ls 2>/dev/null
echo "--- 启动脚本、登录脚本、SSH 公钥 ---"
grep -vE '^\s*(#|$)' /etc/rc.d/rc.local 2>/dev/null | grep -v 'touch /var/lock/subsys/local'
find /etc/profile /etc/profile.d /etc/bashrc /root/.bashrc /root/.bash_profile /home/*/.bashrc \
     /root/.ssh /home/*/.ssh /etc/ssh/sshd_config -newermt "$SINCE" -ls 2>/dev/null
for k in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$k" ] && echo "[$k]" && awk '{print $NF}' "$k"; done
echo "--- 新增账号 / UID 为 0 的账号 ---"
awk -F: '$3==0{print "UID0: "$1}' /etc/passwd
find /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d -newermt "$SINCE" -ls 2>/dev/null

# ---------------------------------------------------------------------
sec "6. 系统程序被替换（rpm 哈希校验，约 1–3 分钟）"
rpm -Va 2>/dev/null | grep -E '^..5' | grep -vE ' c /' | grep -E ' /(usr/)?(s?bin|lib|lib64|libexec)/' \
  || echo "OK：系统目录中的程序与安装包一致"

# ---------------------------------------------------------------------
sec "7. 可疑位置的 ELF 可执行文件与脚本"
find /tmp /var/tmp /dev/shm /run /root /home /opt /usr/local /var/spool /var/lib -xdev -type f -size +8k \
     -newermt "$SINCE" 2>/dev/null | while read -r f; do
  if head -c4 "$f" 2>/dev/null | grep -q 'ELF'; then
    [[ "$f" =~ $KNOWN_PREFIX ]] && continue
    echo "ELF $(stat -c '%y %U %s' "$f") $f  sha256=$(sha256sum "$f" | cut -c1-64)"
  fi
done
find / -xdev -type d -name '.*' \( -path '/tmp/*' -o -path '/var/tmp/*' -o -path '/dev/shm/*' -o -path '/usr/*' -o -path '/etc/*' -o -path '/opt/www/*' \) 2>/dev/null \
  | grep -vE '/\.(git|cache|svn|build-id)' | sed 's/^/隐藏目录: /'
echo "--- 网站目录中最近新增的 PHP 文件 ---"
find /opt/www -xdev -name '*.php' -newermt "$SINCE" -not -path '*/vendor/*' -not -path '*/storage/framework/*' -ls 2>/dev/null

echo; echo "报告已保存：$OUT"
echo "下一步：对标记为 !! 或出现在第 1、4、7 节的条目，执行"
echo "  cp /proc/<PID>/exe /root/sample_<PID>.bin; sha256sum /root/sample_<PID>.bin"
echo "  tr '\\0' ' ' < /proc/<PID>/cmdline; echo; ls -l /proc/<PID>/cwd"
echo "然后再处置（先取证，后终止进程）。"
