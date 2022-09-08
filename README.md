#
# Sandbox Scryer
#
# Version:  1.0.4
#
# License:  GPL v3
#



The Sandbox Scryer is an open-source tool for producing threat hunting and intelligence data from public sandbox detonation output
The tool leverages the MITRE ATT&CK Framework to organize and prioritize findings, assisting in the assembly of IOCs, understanding attack movement and in threat hunting
By allowing researchers to send thousands of samples to a sandbox for building a profile that can be used with the ATT&CK technique, the Sandbox Scryer delivers an
   unprecedented ability to solve use cases at scale
The tool is intended for cybersecurity professionals who are interested in threat hunting and attack analysis leveraging sandbox output data.
The Sandbox Scryer tool currently consumes output from the free and public Hybrid Analysis malware analysis service helping analysts expedite and scale threat hunting



# Repository contents

[root]
   __version__.txt    -  Current tool version
   LICENSE            -  Defines license for source and other contents
   README.md          -  This file

[root\bin]
   \Linux       -  Pre-build binaries for running tool in Linux.  Currently supports:  Ubuntu x64
   \MacOS       -  Pre-build binaries for running tool in MacOS.  Currently supports:  OSX 10.15 x64
   \Windows     -  Pre-build binaries for running tool in Windows.  Currently supports:  Win10 x64

[root\presentation_video]
   Sandbox_Scryer__BlackHat_Presentation_and_demo.mp4     -  Video walking through slide deck and showing demo of tool


[root\screenshots_and_videos]
   Various backing screenshots

[root\scripts]
   Parse_report_set.*    -  Windows PowerShell and DOS Command Window batch file scripts that invoke tool to parse each HA Sandbox report summary in test set
   Collate_Results.*     -  Windows PowerShell and DOS Command Window batch file scripts that invoke tool to collate data from parsing report summaries and generate
                               a MITRE Navigator layer file

[root\slides]
   BlackHat_Arsenal_2022__Sandbox_Scryer__BH_template.pdf    -  PDF export of slides used to present the Sandbox Scryer at Black Hat 2022

[root\src]
   Sandbox_Scryer    -  Folder with source for Sandbox Scryer tool (in c#) and Visual Studio 2019 solution file

[root\test_data]
   (SHA256 filenames).json                   -  Report summaries from submissions to Hybrid Analysis
   enterprise-attack__062322.json            -  MITRE CTI data
   TopAttackTechniques__High__060922.json    -  Top MITRE ATT&CK techniques generated with the MITRE calculator.  Used to rank techniques for generating heat map in MITRE Navigator

[root\test_output]
   (SHA256)_report__summary_Error_Log.txt              -  Errors (if any) encountered while parsing report summary for SHA256 included in name
   (SHA256)_report__summary_Hits__Complete_List.png    -  Graphic showing tecniques noted while parsing report summary for SHA256 included in name
   (SHA256)_report__summary_MITRE_Attck_Hits.csv       -  For collation step, techniques and tactics with select metadata from parsing report summary for SHA256 included in name
   (SHA256)_report__summary_MITRE_Attck_Hits.txt       -  More human-readable form of .csv file.  Includes ranking data of noted techniques

   \collated_data
      collated_080122_MITRE_Attck_Heatmap.json         -  Layer file for import into MITRE Navigator



# Operation

The Sandbox Scryer is intended to be invoked as a command-line tool, to facilitate scripting

Operation consists of two steps:
   - Parsing, where a specified report summary is parsed to extract the output noted earlier
   - Collation, where the data from the set of parsing results from the parsing step is collated to produce a Navigator layer file

Invocation examples:
   - Parsing

   - Collation

   If the parameter "-h" is specified, the built-in help is displayed as shown here
      Sandbox_Scryer.exe -h

            Options:
               -h  Display command-line options
               -i  Input filepath
               -ita  Input filepath - MITRE report for top techniques
               -o  Output folder path
               -ft Type of file to submit
               -name Name to use with output
               -sb_name Identifier of sandbox to use  (default:  ha)
               -api_key API key to use with submission to sandbox
               -env_id Environment ID to use with submission to sandbox
               -inc_sub Include sub-techniques in graphical output  (default is to not include)
               -mitre_data Filepath for mitre cti data to parse (to populate att&ck techniques)
               -cmd  Command
                     Options:
                        parse  Process report file from prior sandbox submission
                               Uses -i, -ita, -o, -name, -inc_sub, -sig_data   parameters
                        col    Collates report data from prior sandbox submissions
                               Uses -i (treated as folder path), -ita, -o, -name, -inc_sub, -mitre_data   parameters


Once the Navigator layer file is produced, it may be loaded into the Navigator for viewing via
   https://mitre-attack.github.io/attack-navigator/

Within the Navigator, techniques noted in the sandbox report summaries are highlighted and shown with increased heat based on a combined scoring of the technique ranking
   and the count of hits on the technique in the sandbox report summaries.  Howevering of techniques will show select metadata.








