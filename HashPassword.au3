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
; Author ........: Christian Bendt (M3d1c5)
; Modified ......:
; Remarks .......: SHA-512 only works with Windows XP SP3 and later
; Related .......: _CheckPassword
; Link ..........: https://github.com/M3d1c5/HashPassword.au3
;===============================================================================
Func _HashPassword($inPwd, $inSalt = "")
	Local Const $CALG_SHA512 = 0x0000800e
	Local $hAlg = $CALG_SHA512
	Local $aChar[3], $sSalt, $sHash, $sPassword, $i
	Local $sPassword = StringStripWS($inPwd, 1 + 2)

	If $inSalt = "" Then
		For $i = 1 To 40
			$aChar[0] = Chr(Random(65, 90, 1)) ;A-Z
			$aChar[1] = Chr(Random(97, 122, 1)) ;a-z
			$aChar[2] = Chr(Random(48, 57, 1)) ;0-9
			$sSalt &= $aChar[Random(0, 2, 1)]
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
; Author ........: Christian Bendt (M3d1c5)
; Modified ......:
; Remarks .......:
; Related .......: _HashPassword
; Link ..........: https://github.com/M3d1c5/HashPassword.au3
;===============================================================================
Func _CheckPassword($inPwd, $inHash)
	Local $sHash, $sSalt
	Local $sPassword = StringStripWS($inPwd, 1 + 2)
	Local $aHash = StringSplit($inHash, "$")

	If $sPassword = "" Then Return False
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