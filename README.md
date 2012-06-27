HashPassword.au3
================

An AutoIt UDF to salt, hash and check passwords.

Installation
------------

Copy the file `HashPassword.au3` to the directory of your script.

Usage
-----

    #include "HashPassword.au3"
    Local $Password = InputBox("HashPassword", "Enter the password to hash", "", "*")
    Local $Hash = _HashPassword($Password)
    MsgBox(0, "HashPassword", "The Hash: " & $Hash)
    Local $RePassword = InputBox("HashPassword", "Enter the password to check it against the hash", "", "*")
    If _CheckPassword($RePassword, $Hash) = True Then
        MsgBox(0, "HashPassword", "Password is correct!")
    Else
        MsgBox(0, "HashPassword", "Password is not correct!")
    EndIf

How it works
------------

A random string (the salt) will be added to the password: `SecretPasswordr5sa3MJL65WbS2Y0qx43S1IW9PnIj2d43awK1Y3Q`  
This new string will be hashed with SHA512 hash algorythm 256 times.  
The resulting hash and the used salt is returned as one string seperated by `$`.

Discussions
-----------

You can join the discussion on [AutoIt.de](http://www.autoit.de/index.php?page=Thread&threadID=32128).

