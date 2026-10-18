cat > grab.sh <<'EOF'
#!/bin/bash
[ "$(id -u)" -eq 0 ] || { echo "错误：请用 root 执行"; exit 1; }
PIDS=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E 'tcp_linux|/tmp/.*\(deleted\)' | sed -E 's#.*/proc/([0-9]+)/exe.*#\1#')
[ -z "$PIDS" ] && { echo "未找到 tcp_linux_amd64 进程（可能已退出或改了名）"; ps -eo pid,user,lstart,comm,args | grep -E '\[kworker' | grep -v grep | head; exit 1; }
D=/root/ir_tcp_$(date +%m%d%H%M); mkdir -p "$D"
for P in $PIDS; do
  echo "== 处理 PID $P"
  cp /proc/$P/exe "$D/sample_$P.bin" && echo "  样本已保存：$(sha256sum "$D/sample_$P.bin")" || echo "  样本复制失败"
  tr '\0' ' '  < /proc/$P/cmdline > "$D/cmdline_$P.txt"; echo "  命令行：$(cat "$D/cmdline_$P.txt")"
  tr '\0' '\n' < /proc/$P/environ > "$D/environ_$P.txt" 2>&1
  cat /proc/$P/status > "$D/status_$P.txt"
  ps -o pid,ppid,user,lstart,etime,comm,args -p $P | tee "$D/ps_$P.txt"
  ls -l /proc/$P/fd > "$D/fd_$P.txt" 2>&1
  ls -l /proc/$P/cwd > "$D/cwd_$P.txt" 2>&1
  ss -antpe 2>/dev/null | grep "pid=$P," | tee "$D/conn_$P.txt"
  cat /proc/$P/net/tcp > "$D/net_tcp_$P.txt"
done
cp /root/.bash_history "$D/root_history.txt" 2>/dev/null
ss -antpe > "$D/ss_all.txt" 2>&1
ps auxwwf > "$D/ps_tree.txt"
cd /root && tar czf "$D.tgz" "$(basename "$D")" && echo && echo "完成：$D.tgz（$(du -h "$D.tgz" | cut -f1)）"
EOF
