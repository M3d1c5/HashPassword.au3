; ############################################################################
; Copyright (c) 2012 Christian Bendt (M3d1c5) mail@m3d1c5.org
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to
; deal in the Software without restriction, including without limitation the
; rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
; sell copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
; IN THE SOFTWARE.
; ############################################################################

#include-once
#include <Crypt.au3>

; #FUNCTION# ===================================================================
; Name...........: _HashPassword
; Description ...: Salt and Hash password using SHA-512
; Syntax.........: _HashPassword($inPwd [,$inSalt])
; Parameters ....: $inPwd - Password to salt and hash
;                  $inSalt - Salt to to use (optional)
; Return values .: Success - Returns hash and salt as string seperated by "$"
;                  Failure - Returns -1
; Author ........: Christian Bendt (M3d1c5) mail@m3d1c5.org
; Modified ......:
; Remarks .......: SHA-512 only works with Windows XP SP3 and later
; Related .......: _CheckPassword
; Link ..........: http://m3d1c5.github.com/HashPassword.au3
;===============================================================================
Func _HashPassword($inPwd, $inSalt = "")
	Local Const $CALG_SHA512 = 0x0000800e
	Local $hAlg = $CALG_SHA512
	Local $sSalt, $sHash, $sPassword, $i
	Local $sPassword = StringStripWS($inPwd, 1 + 2)
	Local $aSalt=StringSplit("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "")

	If $inSalt = "" Then
		For $i = 1 To 40
			$sSalt &= $aSalt[Random(1, $aSalt[0], 1)]
		Next
	Else
		$sSalt = $inSalt
	EndIf

	If _Crypt_Startup() = False Then
		Return -1
	EndIf

	$sHash = $sPassword & $sSalt
	For $i = 1 To 256
		$sHash = _Crypt_HashData($sHash, $hAlg)
		If $sHash = -1 Then
			Return -1
		Else
			$sHash = StringMid($sHash, 3)
		EndIf
	Next
	_Crypt_Shutdown()

	Return $sHash & "$" & $sSalt
EndFunc   ;==>_HashPassword

; #FUNCTION# ===================================================================
; Name...........: _CheckPassword
; Description ...: Check password against given hash
; Syntax.........: _CheckPassword($inPwd, $inHash)
; Parameters ....: $inPwd - Password to check
;                  $inHash - Hash and salt seperated by "$" to check password with
; Return values .: Success - Returns True
;                  Failure - Returns False
; Author ........: Christian Bendt (M3d1c5) mail@m3d1c5.org
; Modified ......:
; Remarks .......:
; Related .......: _HashPassword
; Link ..........: http://m3d1c5.github.com/HashPassword.au3
;===============================================================================
Func _CheckPassword($inPwd, $inHash)
	Local $sHash, $sSalt
	Local $aHash = StringSplit($inHash, "$")

	If Not IsArray($aHash) Then Return False
	If $aHash[0] <> 2 Then Return False

	$sHash = $aHash[1]
	$sSalt = $aHash[2]

	If _HashPassword($inPwd, $sSalt) = $inHash Then
		Return True
	Else
		Return False
	EndIf
EndFunc   ;==>_CheckPassword
