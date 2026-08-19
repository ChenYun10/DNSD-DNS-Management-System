#!/usr/bin/env python3
"""SSH 运维辅助脚本（测试用）
用法:
  set SSH_HOST/SSH_USER/SSH_PASS 环境变量
  python scripts/ssh.py run "command"
  python scripts/ssh.py upload <local> <remote>
  python scripts/ssh.py upload-dir <local_dir> <remote_dir>
  python scripts/ssh.py download <remote> <local>
"""
import io, os, stat, sys, tarfile
import paramiko

HOST = os.environ.get("SSH_HOST", "dns.example.com")
USER = os.environ.get("SSH_USER", "root")
PASS = os.environ.get("SSH_PASS", "")


def connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=22, username=USER, password=PASS, timeout=20,
              banner_timeout=20, auth_timeout=20)
    return c


def run(cmd, timeout=600):
    c = connect()
    try:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout, get_pty=True)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        if out.strip():
            print(out.rstrip())
        if err.strip():
            print(err.rstrip(), file=sys.stderr)
        return rc
    finally:
        c.close()


def upload(local, remote):
    c = connect()
    try:
        sftp = c.open_sftp()
        sftp.put(local, remote)
        sftp.close()
        print(f"uploaded {local} -> {remote}")
    finally:
        c.close()


def upload_dir(local_dir, remote_dir):
    """递归上传目录（跳过 .dev/bin/.git）"""
    c = connect()
    try:
        sftp = c.open_sftp()
        skip = {".dev", "bin", ".git", "certs", "node_modules"}
        for root, dirs, files in os.walk(local_dir):
            dirs[:] = [d for d in dirs if d not in skip]
            rel = os.path.relpath(root, local_dir)
            rdir = remote_dir if rel == "." else remote_dir + "/" + rel.replace("\\", "/")
            try:
                sftp.mkdir(rdir)
            except IOError:
                pass
            for f in files:
                lp = os.path.join(root, f)
                rp = rdir + "/" + f
                try:
                    sftp.stat(rp)
                    # 只覆盖更小的/不同的：简单起见总是覆盖
                except IOError:
                    pass
                sftp.put(lp, rp)
        sftp.close()
        print(f"uploaded dir {local_dir} -> {remote_dir}")
    finally:
        c.close()


def download(remote, local):
    c = connect()
    try:
        sftp = c.open_sftp()
        sftp.get(remote, local)
        sftp.close()
        print(f"downloaded {remote} -> {local}")
    finally:
        c.close()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "run":
        sys.exit(run(sys.argv[2]))
    elif cmd == "upload":
        upload(sys.argv[2], sys.argv[3])
    elif cmd == "upload-dir":
        upload_dir(sys.argv[2], sys.argv[3])
    elif cmd == "download":
        download(sys.argv[2], sys.argv[3])
    else:
        print("unknown subcommand", file=sys.stderr)
        sys.exit(2)
