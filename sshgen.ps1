<#
 .Synopsis
  A series of functions made to increase SSH ease of use on windows 10+.

 .Description
  An sshgen function that streamlines custom SSH generation on Windows Platforms

 .Parameter l_machine
  local machine. automatically defined if not specified

 .Parameter r_machine
  remote machine. Not automatically defined, required to use Push-Remote function

 .Parameter r_machine_type
 remote machine type, default linux, can be windows/unix. Push-Remote defines this based on packet ttl, used to set remote authorized keys path

 .Parameter alg
  encryption algorithim. defaults to ed25519. as this is a wrapper for ssh-keygen so same options apply.

 .Parameter bits
 bit passes on key. defaults to 4096
 
 .Parameter privpath
 path to private keyfile. Set automatically
 
 .Parameter pubpath
 path to public keyfile. Set automatically
 
 .Parameter r_auth_path
 path to authorized_keys file. Set automatically

 .Example
   # generate an ssh priv/pub keypair tagged with the local machine hostname.
   sshgen <local_machine> <remote_machine> 

#>
#This little "wrapper" does a series of things in order:
#
#  1. Take descriptive input for an SSH key
#  2. Generate a local and remote key
#  3. Removes Windows ACL permissions which causes SSH to refuse to function w/ Windows
#  4. Attempt to push the remote key to the remote host
#  5. If successful, amend local SSH config file with remote host entry for passwordless SSH

function sshgen {
	param (
	[string]$local  = $env:computername,
	[Parameter(Mandatory=$true)]
	[string]$remote = '',
    [string]$r_machine_type = 'Linux',
    [string]$r_user   = '',
	[string]$priv_path = "",
	[string]$pub_path = "",
	[string]$alg    = 'ed25519',
	[string]$bits   = 4096,
    [Switch]$verbose = $false,
    [Switch]$nopush = $false
	)

#generate descriptive filename and keypaths
  $keysfor = $local + "-" + $remote
  $privpath = "$env:USERPROFILE\.ssh\$keysfor"
  $pubpath = "$env:USERPROFILE\.ssh\$keysfor.pub" 
#make sure you didn't fuck it up
  if ($verbose -eq $true){
	Write-Host "Local: $local"
	Write-Host "Remote: $remote"
	Write-Host "KeyName: $keysfor"
	Write-host "Privpath: $privpath"
	Write-host "Pubpath: $pubpath"
    Write-host "Alg: $alg"
	Write-host "Bits: $bits"
    
  }
	
#generate priv/pub keypair. Comments and passphrase bypass add issues so excluded
  ssh-keygen -b $bits -f $sshvars.privpath -t $alg

#ACL cleanup to prevent SSH making a fuss
  Remove-ACLEntries $sshvars.privpath
  Remove-ACLEntries $sshvars.pubpath
  Write-Host "Windows ACLs removed"

#add priv key to ssh-agent
  $priv = $sshvars.privpath
  ssh-add $priv

#If Remote Machine provided, add pub key to remote host auth'd keys and test
  $file = "$env:USERPROFILE\.ssh\config"
  if ($remote -ne '' -and $nopush -eq $false){
    Write-Host "Pushing Remote"
	#set an error variable
	#attempt to give the remote system the pub file
	$erred = $false
	try{ 
		Push-Remote $remote 
	}catch { 
		"Unable to push remote. Stopping remote push"
		break
	}
	#Add passwordless entry to local SSH config file
	Add-Content -Path $file -value "
  Host $remote
  HostName $remote
  User $user
  PubkeyAuthentication yes
  IdentityFile $priv
"	
	#trust, but verify SSH functionality
    try {
      ssh $remote "echo from $HOSTNAME SSH Key Functional && exit"
    }catch{
      throw $_.Exception.Message
    }
   }
}


#Add pubkey to remote authorized keys
function Push-Remote ($remote)
{
  try{
    Write-Host "Detecting Remote Type"
    #determine remote host type by packet TTL
	$TimeToLive = Test-Connection $remote -Count 1 | select-object -exp ResponseTimeToLive 
    $r_machine_type = Switch($TimeToLive)
    { {$_ -le 64} {"Linux"; break}
      {$_ -le 128} {"Windows"; break}
      {$_ -le 255} {"UNIX"; break}
    }
    Write-Host "Remote Type: " $r_machine_type
	
	#regardless of user this will still pop a login window. just prefills the user
	if($r_user -ne ''){
		$login = $r_user + "@" + $remote
	}else{
		$login = $remote
	}
    Write-Host "Login Set: " $login
    Write-Host "Adding Pub Key to Remote Authorized Key File"
    if ($sshvars.r_machine_type -eq "Windows"){
      $r_auth_path = "C:\ProgramData\ssh\administrators_authorized_keys"
      Get-Content $sshvars.pubpath | ssh $login "cat >> $r_auth_path"
    }elseif($sshvars.r_machine_type -eq "Linux"){
      $r_auth_path = $sshvars.r_auth_path
      $key = Get-Content $sshvars.pubpath
      ssh -t $login "sudo mkdir -p .ssh && chmod 700 .ssh && touch .ssh/authorized_keys && chmod 600 .ssh/authorized_keys  && echo $key  >> $r_auth_path"
    }else{
      Write-host "Unix not supported lol"
    }
  }catch{
    Write-host "Error: $_"
  }
}

#function to remove Windows ACL Entries so SSH doesn't throw an error about secturiy perms
function Remove-ACLEntries
{
    param(
        [string]$File
    )
    $authusers = ((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-11').Translate([System.Security.Principal.NTAccount])).Value
    $acl = Get-Acl $File
    $acl.SetAccessRuleProtection($True, $False)
    $owner = $acl.owner;
    For($i=$acl.Access.Count - 1; $i -gt -1; $i--)
    {
        $rule = $acl.Access[$i]
        if ($rule.IdentityReference -ne $owner -or $rule.IdentityReference -eq $authusers) 
        {
            $acl.RemoveAccessRule($rule)
        }
    }
    Set-ACL -Path $file -AclObject $acl | Out-Null
}