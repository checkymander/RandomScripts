#Import-Module base64encodedecode.ps1
#Invoke-base64Decode("filename.txt")
#Invoke-base64Encode("filename.txt")

function Invoke-base64Encode($filename) {
$Text = Get-Content $filename
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
}


function Invoke-base64Decode($filename) {

$encodedText = Get-Content $filename
$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
$DecodedText
}
