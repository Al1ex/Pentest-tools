###############################################################################################################
# Language     :  PowerShell 4.0
# Filename     :  IPv4PortScan.ps1 
# Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
# Description  :  Powerful asynchronus IPv4 Port Scanner
# Repository   :  https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner
###############################################################################################################

<#
    .SYNOPSIS
    Powerful asynchronus IPv4 Port Scanner

    .DESCRIPTION
    This powerful asynchronus IPv4 Port Scanner allows you to scan every Port-Range you want (500 to 2600 would work). Only TCP-Ports are scanned. 

    The result will contain the Port number, Protocol, Service name, Description and the Status.
    
    .EXAMPLE
    .\IPv4PortScan.ps1 -ComputerName fritz.box -EndPort 500

    Port Protocol ServiceName  ServiceDescription               Status
    ---- -------- -----------  ------------------               ------
      53 tcp      domain       Domain Name Server               open
      80 tcp      http         World Wide Web HTTP              open
    
    .LINK
    https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner/blob/master/README.md
#>

[CmdletBinding()]
param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        HelpMessage='ComputerName or IPv4-Address of the device which you want to scan')]
    [String]$ComputerName,

    [Parameter(
        Position=1,
        HelpMessage='First port which should be scanned (Default=1)')]
    [ValidateRange(1,65535)]
    [Int32]$StartPort=1,

    [Parameter(
        Position=2,
        HelpMessage='Last port which should be scanned (Default=65535)')]
    [ValidateRange(1,65535)]
    [ValidateScript({
        if($_ -lt $StartPort)
        {
            throw "Invalid Port-Range!"
        }
        else 
        {
            return $true
        }
    })]
    [Int32]$EndPort=65535,

    [Parameter(
        Position=3,
        HelpMessage='Maximum number of threads at the same time (Default=500)')]
    [Int32]$Threads=500,

    [Parameter(
        Position=4,
        HelpMessage='Execute script without user interaction')]
    [switch]$Force
)

Begin{
    Write-Verbose -Message "Script started at $(Get-Date)"

    $PortList_Path = "$PSScriptRoot\Resources\ports.txt"
}

Process{
    if(Test-Path -Path $PortList_Path -PathType Leaf)
    {        
        $PortsHashTable = @{ }

        Write-Verbose -Message "Read ports.txt and fill hash table..."

        foreach($Line in Get-Content -Path $PortList_Path)
        {
            if(-not([String]::IsNullOrEmpty($Line)))
            {
                try{
                    $HashTableData = $Line.Split('|')
                    
                    if($HashTableData[1] -eq "tcp")
                    {
                        $PortsHashTable.Add([int]$HashTableData[0], [String]::Format("{0}|{1}",$HashTableData[2],$HashTableData[3]))
                    }
                }
                catch [System.ArgumentException] { } # Catch if port is already added to hash table
            }
        }

        $AssignServiceWithPort = $true
    }
    else 
    {
        $AssignServiceWithPort = $false    

        Write-Warning -Message "No port-file to assign service with port found! Execute the script ""Create-PortListFromWeb.ps1"" to download the latest version.. This warning doesn`t affect the scanning procedure."
    }

    # Check if host is reachable
    Write-Verbose -Message "Test if host is reachable..."
    if(-not(Test-Connection -ComputerName $ComputerName -Count 2 -Quiet))
    {
        Write-Warning -Message "$ComputerName is not reachable!"

        if($Force -eq $false)
        {
            $Title = "Continue"
            $Info = "Would you like to continue? (perhaps only ICMP is blocked)"
            
            $Options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
            [int]$DefaultChoice = 0
            $Opt =  $host.UI.PromptForChoice($Title , $Info, $Options, $DefaultChoice)

            switch($Opt)
            {                    
                1 { 
                    return
                }
            }
        }
    }

    $PortsToScan = ($EndPort - $StartPort)

    Write-Verbose -Message "Scanning range from $StartPort to $EndPort ($PortsToScan Ports)"
    Write-Verbose -Message "Running with max $Threads threads"

    # Check if ComputerName is already an IPv4-Address, if not... try to resolve it
    $IPv4Address = [String]::Empty
	
	if([bool]($ComputerName -as [IPAddress]))
	{
		$IPv4Address = $ComputerName
	}
	else
	{
		# Get IP from Hostname (IPv4 only)
		try{
			$AddressList = @(([System.Net.Dns]::GetHostEntry($ComputerName)).AddressList)
			
			foreach($Address in $AddressList)
			{
				if($Address.AddressFamily -eq "InterNetwork") 
				{					
					$IPv4Address = $Address.IPAddressToString 
					break					
				}
			}					
		}
		catch{ }	# Can't get IPAddressList 					

       	if([String]::IsNullOrEmpty($IPv4Address))
		{
			throw "Could not get IPv4-Address for $ComputerName. (Try to enter an IPv4-Address instead of the Hostname)"
		}		
	}

    # Scriptblock --> will run in runspaces (threads)...
    [System.Management.Automation.ScriptBlock]$ScriptBlock = {
        Param(
			$IPv4Address,
			$Port
        )

        try{                      
            $Socket = New-Object System.Net.Sockets.TcpClient($IPv4Address,$Port)
            
            if($Socket.Connected)
            {
                $Status = "Open"             
                $Socket.Close()
            }
            else 
            {
                $Status = "Closed"    
            }
        }
        catch{
            $Status = "Closed"
        }   

        if($Status -eq "Open")
        {
            [pscustomobject] @{
                Port = $Port
                Protocol = "tcp"
                Status = $Status
            }
        }
    }

    Write-Verbose -Message "Setting up RunspacePool..."

    # Create RunspacePool and Jobs
    $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
    $RunspacePool.Open()
    [System.Collections.ArrayList]$Jobs = @()

    Write-Verbose -Message "Setting up Jobs..."
    
    #Set up job for each port...
    foreach($Port in $StartPort..$EndPort)
    {
        $ScriptParams =@{
			IPv4Address = $IPv4Address
			Port = $Port
		}

        # Catch when trying to divide through zero
        try {
			$Progress_Percent = (($Port - $StartPort) / $PortsToScan) * 100 
		} 
		catch { 
			$Progress_Percent = 100 
		}

        Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current Port: $Port" -PercentComplete ($Progress_Percent)
        
        # Create mew job
        $Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameters($ScriptParams)
        $Job.RunspacePool = $RunspacePool
        
        $JobObj = [pscustomobject] @{
            RunNum = $Port - $StartPort
            Pipe = $Job
            Result = $Job.BeginInvoke()
        }

        # Add job to collection
        [void]$Jobs.Add($JobObj)
    }

    Write-Verbose -Message "Waiting for jobs to complete & starting to process results..."

    # Total jobs to calculate percent complete, because jobs are removed after they are processed
    $Jobs_Total = $Jobs.Count

     # Process results, while waiting for other jobs
    Do {
        # Get all jobs, which are completed
        $Jobs_ToProcess = $Jobs | Where-Object -FilterScript {$_.Result.IsCompleted}
  
        # If no jobs finished yet, wait 500 ms and try again
        if($null -eq $Jobs_ToProcess)
        {
            Write-Verbose -Message "No jobs completed, wait 500ms..."

            Start-Sleep -Milliseconds 500
            continue
        }
        
        # Get jobs, which are not complete yet
        $Jobs_Remaining = ($Jobs | Where-Object -FilterScript {$_.Result.IsCompleted -eq $false}).Count

        # Catch when trying to divide through zero
        try {            
            $Progress_Percent = 100 - (($Jobs_Remaining / $Jobs_Total) * 100) 
        }
        catch {
            $Progress_Percent = 100
        }

        Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete $Progress_Percent -Status "$Jobs_Remaining remaining..."
      
        Write-Verbose -Message "Processing $(if($null -eq $Jobs_ToProcess.Count){"1"}else{$Jobs_ToProcess.Count}) job(s)..."

        # Processing completed jobs
        foreach($Job in $Jobs_ToProcess)
        {       
            # Get the result...     
            $Job_Result = $Job.Pipe.EndInvoke($Job.Result)
            $Job.Pipe.Dispose()

            # Remove job from collection
            $Jobs.Remove($Job)
           
            # Check if result is null --> if not, return it
            if($Job_Result.Status)
            {        
                if($AssignServiceWithPort)
                {
                    $Service = [String]::Empty

                    $Service = $PortsHashTable.Get_Item($Job_Result.Port).Split('|')
                
                    [pscustomobject] @{
                        Port = $Job_Result.Port
                        Protocol = $Job_Result.Protocol
                        ServiceName = $Service[0]
                        ServiceDescription = $Service[1]
                        Status = $Job_Result.Status
                    }
                }   
                else 
                {
                    $Job_Result    
                }             
            }
        } 

    } While ($Jobs.Count -gt 0)
    
    Write-Verbose -Message "Closing RunspacePool and free resources..."

    # Close the RunspacePool and free resources
    $RunspacePool.Close()
    $RunspacePool.Dispose()

    Write-Verbose -Message "Script finished at $(Get-Date)"
}

End{

}
