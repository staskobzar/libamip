## libanip: Asterisk Manager Interface Library

Simple library for manipulating and parsing AMI (Asterisk Manager Interface)
written with C and re2c for parcing. 
It does not provide any network capabilities. 
Can be used with other network libraries like APR or in extenstions for Ruby or Python.

### Install
```
./configure
make
sudo make install
```

### Development
Using cmocka for UnitTest developement.

To run tests:
```
make check
```

### Docs
Run ```make``` and check "doc/html/index.html".

See example in "example" directory.
