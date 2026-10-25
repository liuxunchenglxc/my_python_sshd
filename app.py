# pip install 'asyncssh[bcrypt,fido2,gssapi,ifaddr,pkcs11,pyOpenSSL]'
import asyncio, asyncssh, bcrypt, sys, subprocess, os
from typing import Optional

user_name = "e57a7d70fe7c30a"
user_pwd = b"f92cc948f4f5"
server_port = 20340
server_host_key = "katabump01_sshkey"

passwords = {
    user_name: bcrypt.hashpw(user_pwd, bcrypt.gensalt()),
}

PUBLIC_KEYS = {
    "e57a7d70fe7c30a": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC4qoMsF8H37sWBnCxSMjF1alcx9vfQ6SEiinc9X/Xu/SS+z9+IIaSgCFkN7/0p8LI+wYNTaiXv7cjiaCg/WpI3Z+QJFv6ekmCepFK9gROUsq2ngLTcHnm09eYj60YH47EfmspwHRR+28OHFUbKAbn9GpjukgsSDTxLSjepo9sIVPh8T2lhfRZUDxUCMOeVdw6guy1Kmz4tQlB90rH0VLfIWjFQvFM/swNGxHLaXyW+9QQ3qyW45aVTK8hrjBbgkMKp0+QQh522f06bl08b28c2P23Tbogx6N87vNAP4GOsmnLkhO5cozUASHIdOWdkLnwx2E4smcpba1ZflDKdSbRRFQW8otFpOTNNISrGzBp5DT6kOma7mkpTqGFSrStUJGGxwnkk+TExgpCQkT5Z1CZxiqGOSB5ffIpgyIEilsLVeA97/FAf1u2wn5Cov6eBJGbAmaqNGHKjQz7ThmPGpCg/c1gwV5TftKJZs3AlJn0V6ZHqmAAFIXezgXoPoNGNyfXDQjfARF2bfgKuz/tMcXnDy/IXwIGHusGKMsgBp9KzTpVJTqdLErV8XmWaS96j3ja0ZvW9yUcSoLa1OhTJ7mjxbpVHjBJ7BRc/ll/O3bjhmH6b8YjmtEVbyfJSq9JlpAkJ/Zg9gwJFj53J603ccRNiaiHbAAmknTTEXJwOas3hwQ== lxc@server_jump",
}

async def handle_client(process: asyncssh.SSHServerProcess) -> None:
    bc_proc = subprocess.Popen('bash -i', shell=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    await process.redirect(stdin=bc_proc.stdin, stdout=bc_proc.stdout,
                           stderr=bc_proc.stderr)
    await process.stdout.drain()
    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peername = conn.get_extra_info('peername')[0]
        self._conn = conn
        print(f'SSH connection received from {peername}.')

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
        else:
            print('SSH connection closed.')

    def begin_auth(self, username: str) -> bool:
        public_key = PUBLIC_KEYS.get(username)

        if public_key:
            self._conn.set_authorized_keys(
                asyncssh.import_authorized_keys(public_key)
            )

        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if username not in passwords:
            return False
        pw = passwords[username]
        if not password and not pw:
            return True
        return bcrypt.checkpw(password.encode('utf-8'), pw)
    
    def connection_requested(self, dest_host: str, dest_port: int,
                             orig_host: str, orig_port: int) -> \
            asyncssh.SSHSocketSessionFactory:
        return True
    
    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        return True

async def start_server() -> None:
    await asyncssh.create_server(MySSHServer, '', server_port,
                                 server_host_keys=[server_host_key,],
                                 process_factory=handle_client, sftp_factory=True, allow_scp=True)

loop = asyncio.new_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
