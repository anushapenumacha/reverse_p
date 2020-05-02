rule AthenaBotNet
{
	meta:
		Description  = "Athena-Bot-Net"
		ThreatLevel  = "5"

	strings:

		$ = "acrotray.exe" ascii wide
		$ = "jusched.exe" ascii wide
		$ = "evil.pdf" ascii wide
        $ = "#NotAnIRCChannel" ascii wide
        $ = "Athena-v2.4.1l" ascii wide
        $ = "665258351" ascii wide


	condition:
		2 of them
}
