<#
 
.SYNOPSIS
Script para automatizar la extracción de eventos de Windows
 
.DESCRIPTION
A través de este script se podrán automatizar tareas de extracción de eventos en 2K8
Los parámetros que admite son los siguientes:

-Path: Ruta y fichero para la extracción

-EventID: Extracción de un evento en particular

- StartDays: Si se quiere filtrar por días concretos

- EndDays: Si se quiere filtrar por días concretos

.EXAMPLE
Extraer eventos de tipo 7045 en LOG SYSTEM
.\Logs.ps1 -Path .\System.evtx -EventID 7045

.EXAMPLE
Extraer eventos de inicio de sesión de hace 15 días en LOG SECURITY
.\Logs.ps1 -Path .\Security.evtx -StartDays 15

.EXAMPLE
Extraer eventos de inicio de sesión de hace 15 días en LOG SECURITY, con el evento 7045
.\Logs.ps1 -Path .\Security.evtx -StartDays 15 -EventID 7045

.EXAMPLE
Extraer eventos de tipo 7045 en LOG SYSTEM, buscando el mensaje PSEXEC
.\Logs.ps1 -Path .\Security.evtx -StartDays 15 -EventID 7045 -message PSEXEC

.LINK
http://www.securitybydefault.com
 
#>

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$false,Position=1)]
   [string]$Path,

   [Parameter(Mandatory=$false)]
   [string]$EventID,

   [Parameter(Mandatory=$false)]
   [int]$StartDate,

   [Parameter(Mandatory=$false)]
   [int]$EndDate,

   [Parameter(Mandatory=$false)]
   [string]$Message
)


#Construct Query
$EventQuery = @{}


if($Path){
    
    $EventQuery["Path"] = $Path
    if(-NOT $StartDate){
        $TempDays = "1/01/1601"
        $EventQuery["StartTime"] = $TempDays
    }
    else{
        $TempDays = (Get-Date).AddDays(-$StartDate)
        $EventQuery["StartTime"] = $TempDays
    }
    if(-NOT $EndDate){
        $EventQuery["EndTime"] = Get-Date
    }
    else{
        $TempDays = (Get-Date).AddDays($EndDate)
        $EventQuery["EndTime"] = $TempDays
    }
    if($Message){
        $EventQuery["Data"] = $Message
    }
    if($EventID){
        $EventQuery["ID"] = $EventID
    }
}

$Data = Get-WinEvent -FilterHashtable $EventQuery -ErrorAction SilentlyContinue
if($Data){
    $Data 
}



