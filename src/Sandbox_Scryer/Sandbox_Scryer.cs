//
// Copyright (c) 2022 CrowdStrike, Inc.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Globalization;
using System.Text.Json.Serialization;
using System.Diagnostics;
using System.Threading;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Reflection;
using Newtonsoft.Json;



namespace Sandbox_Scryer
{



    class Run_Sandbox_Scryer_Command
    {
        private const int attck_Matrix_Image__width = 5000;
        private const int attck_Matrix_Image__height = 5000;
        private const int attck_Matrix_Image__box_width = 315;
        private const int attck_Matrix_Image__box_height = 110;
        private const int attck_Matrix_Image__box_offset_x = 35;
        private const int attck_Matrix_Image__box_offset_y = 5;
        private const int attck_Matrix_Image__box_text_x = 50;
        private const int attck_Matrix_Image__box_text_y = 15;
        private const int attck_Matrix_Image__top_technique__box_width = 30;

        private const int attck_Navigator_Ranking__High_Threshold = 70;
        private const int attck_Navigator_Ranking__Medium_Threshold = 135;
        private const int attck_Navigator_Heatmap_Max_score = 100;
        private const int attck_Navigator_Heatmap_Max_score__High_Ranking = 33;
        private const int attck_Navigator_Heatmap_Max_score__Medium_Ranking = 67;
        private const int attck_Navigator_Heatmap_Max_score__Low_Ranking = 100;


        public class MITRE_ATTACK_Header__Entry
        {
            public string description;
            public List<string> technique_IDs;
            public SortedList<string, MITRE_ATTACK_Data__Entry> entries;
        }

        public class MITRE_ATTACK_Data__Entry
        {
            public bool is_Header;
            public bool entry_Set;
            public string entry_ID;
            public List<string> repeat_Entry_IDs;
            public string parent_Entry_ID;
            public string description;
            public int hit_Count;
            public SortedList<string, string> metadata;
        }

        public class MITRE_ATTACK_Top_Techniques__Entry
        {
            public string entry_ID;
            public int rank;
        }


        enum CTI_File_Parsing_State
        {
            Not_Parsed,
            Tecnique_ID_Parsed,
            Name_Parsed,
            Parsing_Complete
        }


        private Dictionary<string, MITRE_ATTACK_Header__Entry> MITRE_ATTACK_Headers;
        private SortedDictionary<string, MITRE_ATTACK_Data__Entry> MITRE_ATTACK__Data;
        private Dictionary<string, MITRE_ATTACK_Top_Techniques__Entry> MITRE_ATTACK_Top_Techniques;
        private List<string> Error_Log;
        int total_Techniques_Hit;


        private void Init_Logs()
        {

            Error_Log = new List<string>();
            if (Error_Log != null)
            {
                Error_Log.Add("Error Log");
            }
        }


        // Currently, the MITRE ATT&CK headers, which provide the relationship between tactics (column headers) and techniques, are entered via code.
        // Later, will revisit extracting these relationships from the MITRE CTI data.
        //
        // The initialization data is taken from MITRE ATT&CK Framework v11.2.

        private void Init_MITRE_ATTACK_Headers()
        {
            MITRE_ATTACK_Header__Entry new_MITRE_ATTACK_Header__Entry;

            // Headers and techniques taken from ATT&CK v11.2
            // https://attack.mitre.org/

            MITRE_ATTACK_Headers = new Dictionary<string, MITRE_ATTACK_Header__Entry>();

            if (MITRE_ATTACK_Headers != null)
            {
                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Reconnaissance";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1595");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1592");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1589");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1590");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1591");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1598");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1597");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1596");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1593");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1594");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                }


                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Resource Development";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1583");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1586");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1584");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1587");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1585");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1588");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1608");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                }


                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Initial Access";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1189");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1190");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1133");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1200");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1566");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1091");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1195");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1199");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1078");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                }


                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Execution";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1059");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1609");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1610");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1203");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1559");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1106");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1053");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1129");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1072");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1569");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1204");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1047");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                }


                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Persistence";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1098");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1197");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1547");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1037");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1176");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1554");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1136");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1543");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1546");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1133");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1574");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1525");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1556");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1137");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1542");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1053");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1505");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1205");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1078");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                }


                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Privilege Escalation";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1548");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1134");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1547");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1037");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1543");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1484");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1611");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1546");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1068");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1574");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1055");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1053");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1078");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                }


                new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                if (new_MITRE_ATTACK_Header__Entry != null)
                {
                    new_MITRE_ATTACK_Header__Entry.description = "Defense Evasion";
                    new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                    if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1548");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1134");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1197");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1612");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1622");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1140");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1610");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1006");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1484");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1480");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1211");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1222");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1564");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1574");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1562");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1070");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1202");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1036");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1556");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1578");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1112");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1601");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1599");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1027");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1647");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1542");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1055");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1620");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1207");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1014");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1553");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1218");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1216");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1221");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1205");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1127");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1535");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1550");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1078");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1497");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1600");
                        new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1220");
                    }

                    new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                    MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Credential Access";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1557");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1110");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1555");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1212");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1187");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1606");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1056");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1556");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1111");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1621");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1040");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1003");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1528");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1558");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1539");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1552");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Discovery";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1087");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1010");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1217");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1580");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1538");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1526");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1619");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1613");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1622");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1482");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1083");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1615");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1046");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1135");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1040");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1201");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1120");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1069");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1057");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1012");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1018");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1518");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1082");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1614");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1016");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1049");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1033");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1007");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1124");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1497");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Lateral Movement";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1210");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1534");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1570");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1563");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1021");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1091");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1072");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1080");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1550");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Collection";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1557");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1560");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1123");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1119");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1185");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1115");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1530");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1602");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1213");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1005");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1039");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1025");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1074");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1114");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1056");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1113");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1125");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Command and Control";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1071");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1092");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1132");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1001");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1568");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1573");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1008");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1105");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1104");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1095");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1571");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1572");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1090");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1219");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1205");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1102");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Exfiltration";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1020");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1030");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1048");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1041");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1011");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1052");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1567");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1029");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1537");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }


                    new_MITRE_ATTACK_Header__Entry = new MITRE_ATTACK_Header__Entry();
                    if (new_MITRE_ATTACK_Header__Entry != null)
                    {
                        new_MITRE_ATTACK_Header__Entry.description = "Impact";
                        new_MITRE_ATTACK_Header__Entry.technique_IDs = new List<string>();
                        if (new_MITRE_ATTACK_Header__Entry.technique_IDs != null)
                        {
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1531");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1485");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1486");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1565");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1491");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1561");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1499");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1495");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1490");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1498");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1496");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1489");
                            new_MITRE_ATTACK_Header__Entry.technique_IDs.Add("T1529");
                        }

                        new_MITRE_ATTACK_Header__Entry.entries = new SortedList<string, MITRE_ATTACK_Data__Entry>();

                        MITRE_ATTACK_Headers.Add(new_MITRE_ATTACK_Header__Entry.description, new_MITRE_ATTACK_Header__Entry);
                    }
                }
            }
        }

        private List<MITRE_ATTACK_Header__Entry> find_Headers(string technique_ID)
        {
            List<MITRE_ATTACK_Header__Entry> located_MITRE_ATTACK_Header__Entries = new List<MITRE_ATTACK_Header__Entry>();


            if (located_MITRE_ATTACK_Header__Entries != null)
            {
                foreach (MITRE_ATTACK_Header__Entry next_MITRE_ATTACK_Header__Entry in MITRE_ATTACK_Headers.Values)
                {
                    foreach (string next_Entry in next_MITRE_ATTACK_Header__Entry.technique_IDs)
                    {
                        if (next_Entry.ToLower() == technique_ID.ToLower())
                        {
                            located_MITRE_ATTACK_Header__Entries.Add(next_MITRE_ATTACK_Header__Entry);
                        }
                    }
                }
            }

            return located_MITRE_ATTACK_Header__Entries;
        }


        // Checks if a technique is listed under a specified header (tactic).
        
        private bool contains_Entry(MITRE_ATTACK_Header__Entry mitre_ATTACK_Header__Entry, string entry_ID)
        {
            bool retVal;


            retVal = false;

            foreach (MITRE_ATTACK_Data__Entry mitre_ATTACK_Data__Entry in mitre_ATTACK_Header__Entry.entries.Values)
            {
                if ((mitre_ATTACK_Data__Entry.entry_ID != null) && (mitre_ATTACK_Data__Entry.entry_ID.ToUpper() == entry_ID.ToUpper()))
                {
                    retVal = true;
                }
            }

            return retVal;
        }


        // Further populates the data structure for ATT&CK techniques, which builds on the tactic to technique relationship initialized separately.

        private void Init_MITRE_ATTACK_Data__from_file__cti_data(string mitre_init_Data_Filepath)
        {
            string next_Input_Line;
            string tmp_Str;
            string[] tmp_split;
            char[] char_Separators = new char[] { '"', ',' };
            char[] char_Separators__2 = new char[] { '.' };
            string[] split_Input_Line;
            MITRE_ATTACK_Data__Entry new__MITRE_ATTACK_Data__Entry;
            string technique_ID = "";
            string full_technique_ID = "";
            string parent_technique_ID = null;
            string description = "";
            List<MITRE_ATTACK_Header__Entry> mitre_ATTACK_Header__Entries;
            int input_Line_Count;
            CTI_File_Parsing_State cti_File_Parsing_State;


            if (MITRE_ATTACK__Data != null)
            {
                if (mitre_init_Data_Filepath.Length > 0)
                {

                    using (StreamReader streamReader = new StreamReader(mitre_init_Data_Filepath))
                    {
                        input_Line_Count = 0;
                        cti_File_Parsing_State = CTI_File_Parsing_State.Not_Parsed;
                        technique_ID = "";
                        full_technique_ID = "";

                        while (!streamReader.EndOfStream)
                        {
                            next_Input_Line = streamReader.ReadLine();
                            input_Line_Count++;

                            split_Input_Line = next_Input_Line.Split(char_Separators, StringSplitOptions.None);

                            if (next_Input_Line.ToLower().Contains("external_id"))
                            {
                                if ((split_Input_Line.Length >= 3) && (split_Input_Line[1].ToLower().Replace(" ", "") == "external_id") && (split_Input_Line[2].ToLower().Replace(" ", "") == ":") && (split_Input_Line[3].ToLower().Replace(" ", "") != "enterprise-attack"))
                                {
                                    tmp_Str = split_Input_Line[3].ToUpper().Replace(" ", "");

                                    if (tmp_Str[0] == 'T')
                                    {
                                        if (tmp_Str.Contains("."))
                                        {
                                            tmp_split = tmp_Str.Split(char_Separators__2, StringSplitOptions.None);
                                            technique_ID = tmp_split[0].ToUpper();
                                            if ((tmp_split.Length >= 2) && (tmp_split[1].Length > 1))
                                            {
                                                parent_technique_ID = technique_ID;
                                                full_technique_ID = technique_ID + "." + tmp_split[1].ToUpper();
                                            }
                                            else
                                            {
                                                parent_technique_ID = null;
                                                full_technique_ID = technique_ID;
                                            }
                                        }
                                        else
                                        {
                                            technique_ID = split_Input_Line[3].ToUpper().Replace(" ", "");
                                            parent_technique_ID = null;
                                            full_technique_ID = technique_ID;
                                        }

                                        if (cti_File_Parsing_State != CTI_File_Parsing_State.Not_Parsed)
                                        {
                                            cti_File_Parsing_State = CTI_File_Parsing_State.Not_Parsed;
                                        }
                                        else
                                        {
                                            cti_File_Parsing_State = CTI_File_Parsing_State.Tecnique_ID_Parsed;
                                        }
                                    }
                                }
                            }
                            else if (next_Input_Line.ToLower().Contains("name"))
                            {
                                if ((split_Input_Line.Length >= 3) && (split_Input_Line[1].ToLower().Replace(" ", "") == "name") && (split_Input_Line[2].ToLower().Replace(" ", "") == ":"))
                                {
                                    description = split_Input_Line[3];

                                    if (cti_File_Parsing_State == CTI_File_Parsing_State.Tecnique_ID_Parsed)
                                    {
                                        cti_File_Parsing_State = CTI_File_Parsing_State.Parsing_Complete;
                                    }
                                    else
                                    {
                                        cti_File_Parsing_State = CTI_File_Parsing_State.Not_Parsed;
                                    }
                                }
                            }

                            if ((cti_File_Parsing_State == CTI_File_Parsing_State.Parsing_Complete) && (technique_ID[0] == 'T'))
                            {
                                try
                                {
                                    mitre_ATTACK_Header__Entries = find_Headers(technique_ID);
                                    if (mitre_ATTACK_Header__Entries != null)
                                    {
                                        new__MITRE_ATTACK_Data__Entry = new MITRE_ATTACK_Data__Entry();
                                        if (new__MITRE_ATTACK_Data__Entry != null)
                                        {
                                            new__MITRE_ATTACK_Data__Entry.is_Header = false;
                                            new__MITRE_ATTACK_Data__Entry.entry_ID = full_technique_ID;
                                            new__MITRE_ATTACK_Data__Entry.parent_Entry_ID = parent_technique_ID;
                                            new__MITRE_ATTACK_Data__Entry.repeat_Entry_IDs = null;
                                            new__MITRE_ATTACK_Data__Entry.description = description;
                                            new__MITRE_ATTACK_Data__Entry.entry_Set = false;
                                            new__MITRE_ATTACK_Data__Entry.hit_Count = 0;

                                            if (!MITRE_ATTACK__Data.ContainsKey(new__MITRE_ATTACK_Data__Entry.entry_ID))
                                            {
                                                MITRE_ATTACK__Data.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                                            }
                                            else
                                            {
                                                MITRE_ATTACK_Data__Entry tmp_MITRE_ATTACK_Data__Entry;

                                                tmp_MITRE_ATTACK_Data__Entry = MITRE_ATTACK__Data[new__MITRE_ATTACK_Data__Entry.entry_ID];
                                                tmp_MITRE_ATTACK_Data__Entry.description = description;
                                            }

                                            foreach (MITRE_ATTACK_Header__Entry mitre_ATTACK_Header__Entry in mitre_ATTACK_Header__Entries)
                                            {
                                                if ((mitre_ATTACK_Header__Entry != null) && !contains_Entry(mitre_ATTACK_Header__Entry, new__MITRE_ATTACK_Data__Entry.entry_ID))
                                                {
                                                    mitre_ATTACK_Header__Entry.entries.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                                                }
                                                else
                                                {
                                                    //Error_Log.Add("Error - No matching header - MITRE Att&ck technique ID   ID=" + new__MITRE_ATTACK_Data__Entry.entry_ID);
                                                }
                                            }
                                        }
                                    }

                                    if (parent_technique_ID != null)
                                    {
                                        mitre_ATTACK_Header__Entries = find_Headers(technique_ID);
                                        if (mitre_ATTACK_Header__Entries != null)
                                        {
                                            new__MITRE_ATTACK_Data__Entry = new MITRE_ATTACK_Data__Entry();
                                            if (new__MITRE_ATTACK_Data__Entry != null)
                                            {
                                                new__MITRE_ATTACK_Data__Entry.is_Header = false;
                                                new__MITRE_ATTACK_Data__Entry.entry_ID = parent_technique_ID;
                                                new__MITRE_ATTACK_Data__Entry.parent_Entry_ID = null;
                                                new__MITRE_ATTACK_Data__Entry.repeat_Entry_IDs = null;
                                                new__MITRE_ATTACK_Data__Entry.description = description;
                                                new__MITRE_ATTACK_Data__Entry.entry_Set = false;

                                                if (!MITRE_ATTACK__Data.ContainsKey(new__MITRE_ATTACK_Data__Entry.entry_ID))
                                                {
                                                    MITRE_ATTACK__Data.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                                                }

                                                foreach (MITRE_ATTACK_Header__Entry mitre_ATTACK_Header__Entry in mitre_ATTACK_Header__Entries)
                                                {
                                                    if ((mitre_ATTACK_Header__Entry != null) && !contains_Entry(mitre_ATTACK_Header__Entry, new__MITRE_ATTACK_Data__Entry.entry_ID))
                                                    {
                                                        mitre_ATTACK_Header__Entry.entries.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                                                    }
                                                    else
                                                    {
                                                        //Error_Log.Add("Error - Populating matrix - Unknown MITRE Att&ck technique ID   ID=" + new__MITRE_ATTACK_Data__Entry.entry_ID);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                catch (System.ArgumentException)
                                {
                                    Error_Log.Add("Error - Populating matrix - Error adding entry for technique ID =" + full_technique_ID);
                                }

                                cti_File_Parsing_State = CTI_File_Parsing_State.Not_Parsed;
                                technique_ID = "";
                                full_technique_ID = "";
                            }
                        }
                    }
                }
            }

            // Fix up technique descriptions to include description of parent's (if any)
            foreach (MITRE_ATTACK_Data__Entry mitre_ATTACK_Data__Entry in MITRE_ATTACK__Data.Values)
            {
                if (mitre_ATTACK_Data__Entry.parent_Entry_ID != null)
                {
                    if (MITRE_ATTACK__Data.ContainsKey(mitre_ATTACK_Data__Entry.parent_Entry_ID))
                    {
                        MITRE_ATTACK_Data__Entry parent_mitre_ATTACK_Data__Entry;

                        parent_mitre_ATTACK_Data__Entry = MITRE_ATTACK__Data[mitre_ATTACK_Data__Entry.parent_Entry_ID];
                        if (parent_mitre_ATTACK_Data__Entry != null)
                        {
                            mitre_ATTACK_Data__Entry.description = parent_mitre_ATTACK_Data__Entry.description + ": " + mitre_ATTACK_Data__Entry.description;
                        }
                    }
                }
            }
        }


        // Supports further populating ATT&CK matrix via code, versus parsing data such as the CTI data.
        // Allows for fixing up and adding to the matrix if needed.

        private void Init_MITRE_ATTACK_Data__manual()
        {


            // Below are examples of adding additional attck entrie manually, to supplement what is created through automated parsing.
            // Below are commented-out entries for a tactic (header), technique, and sub-technique.  These are just for illustration and should already have been imported through the automated parsing.
            // Adjust the specifics as needed to manually add entries.

            if (MITRE_ATTACK__Data != null)
            {
                //MITRE_ATTACK_Data__Entry new__MITRE_ATTACK_Data__Entry;


                // Start of manually added MITRE Att&ck entries from mitre.org
                // Techniques, sub-techniques, and headers (tactics)

                // Reconnaissance
                //new__MITRE_ATTACK_Data__Entry = new MITRE_ATTACK_Data__Entry();
                //if (new__MITRE_ATTACK_Data__Entry != null)
                //{
                //    new__MITRE_ATTACK_Data__Entry.is_Header = true;
                //    new__MITRE_ATTACK_Data__Entry.entry_ID = "Reconnaissance";
                //    new__MITRE_ATTACK_Data__Entry.repeat_Entry_IDs = null;
                //    new__MITRE_ATTACK_Data__Entry.parent_Entry_ID = null;
                //    new__MITRE_ATTACK_Data__Entry.description = "Reconnaissance";
                //    new__MITRE_ATTACK_Data__Entry.entry_Set = false;
                //    MITRE_ATTACK__Data.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                //}

                //new__MITRE_ATTACK_Data__Entry = new MITRE_ATTACK_Data__Entry();
                //if (new__MITRE_ATTACK_Data__Entry != null)
                //{
                //    new__MITRE_ATTACK_Data__Entry.is_Header = false;
                //    new__MITRE_ATTACK_Data__Entry.entry_ID = "T1595";
                //    new__MITRE_ATTACK_Data__Entry.repeat_Entry_IDs = null;
                //    new__MITRE_ATTACK_Data__Entry.parent_Entry_ID = null;
                //    new__MITRE_ATTACK_Data__Entry.description = "Active Scanning";
                //    new__MITRE_ATTACK_Data__Entry.entry_Set = false;
                //    MITRE_ATTACK__Data.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                //}

                //new__MITRE_ATTACK_Data__Entry = new MITRE_ATTACK_Data__Entry();
                //if (new__MITRE_ATTACK_Data__Entry != null)
                //{
                //    new__MITRE_ATTACK_Data__Entry.is_Header = false;
                //    new__MITRE_ATTACK_Data__Entry.entry_ID = "T1595.001";
                //    new__MITRE_ATTACK_Data__Entry.repeat_Entry_IDs = null;
                //    new__MITRE_ATTACK_Data__Entry.parent_Entry_ID = "T1595";
                //    new__MITRE_ATTACK_Data__Entry.description = "Active Scanning: Scanning IP Blocks";
                //    new__MITRE_ATTACK_Data__Entry.entry_Set = false;
                //    MITRE_ATTACK__Data.Add(new__MITRE_ATTACK_Data__Entry.entry_ID, new__MITRE_ATTACK_Data__Entry);
                //}
            }
        }

        private void Init_MITRE_ATTACK_Data(string mitre_init_Data_Filepath)
        {

            MITRE_ATTACK__Data = new SortedDictionary<string, MITRE_ATTACK_Data__Entry>();


            Init_MITRE_ATTACK_Headers();
            Init_MITRE_ATTACK_Data__from_file__cti_data(mitre_init_Data_Filepath);
            //Init_MITRE_ATTACK_Data__manual();
        }


        // Initialize the ATT&CK top techniques data, using output from the MITRE top techniques calculator
        // 

        private void Init_Top_Techniques_Data(string input_FilePath__TOP_Techniques)
        {
            char[] char_Separators = new char[] { ':', ',' };
            string[] split_Input_Line;
            MITRE_ATTACK_Top_Techniques__Entry new__MITRE_ATTACK_Top_Techniques__Entry;
            string technique_ID = "";
            int rank = -1;


            MITRE_ATTACK_Top_Techniques = new Dictionary<string, MITRE_ATTACK_Top_Techniques__Entry>();

            if (input_FilePath__TOP_Techniques.Length > 0)
            {

                using (StreamReader streamReader = new StreamReader(input_FilePath__TOP_Techniques))
                {
                    while (!streamReader.EndOfStream)
                    {
                        string next_Input_Line;


                        next_Input_Line = streamReader.ReadLine();
                        next_Input_Line = next_Input_Line.Replace(" ", "");
                        next_Input_Line = next_Input_Line.Replace("\"", "");
                        split_Input_Line = next_Input_Line.Split(char_Separators, StringSplitOptions.None);
                        if (split_Input_Line.Length >= 2)
                        {
                            if (split_Input_Line[0].ToLower() == "tid")
                            {
                                technique_ID = split_Input_Line[1].ToUpper();

                                new__MITRE_ATTACK_Top_Techniques__Entry = new MITRE_ATTACK_Top_Techniques__Entry();
                                if (new__MITRE_ATTACK_Top_Techniques__Entry != null)
                                {
                                    new__MITRE_ATTACK_Top_Techniques__Entry.entry_ID = technique_ID;
                                    if (rank != -1)
                                    {
                                        // Rank value already seen for this entry.  We're assuming this will be the case
                                        new__MITRE_ATTACK_Top_Techniques__Entry.rank = rank;
                                    }
                                    MITRE_ATTACK_Top_Techniques.Add(new__MITRE_ATTACK_Top_Techniques__Entry.entry_ID, new__MITRE_ATTACK_Top_Techniques__Entry);
                                }
                            }
                            else if (split_Input_Line[0].ToLower() == "rank")
                            {
                                rank = int.Parse(split_Input_Line[1]);
                            }
                        }
                    }
                }
            }
        }

        public void init_Data(string input_FilePath__TOP_Techniques, string mitre_init_Data_Filepath)
        {

            Init_Logs();
            Init_MITRE_ATTACK_Data(mitre_init_Data_Filepath);
            Init_Top_Techniques_Data(input_FilePath__TOP_Techniques);
        }

        public void Submit_Sample(string input_FilePath, string file_type, string sb_name, string api_key, string environment_ID)
        {

        }


        public void Parse_Sandbox_Report_Summary(string input_FilePath)
        {
            char[] char_Separators = new char[] { '<', '>' };
            string next_metadata_element;


            string complete_Input__Text = File.ReadAllText(input_FilePath);
            //var complete_Input__Json = JsonConvert.DeserializeObject(complete_Input__Text);
            dynamic complete_Input__Json = JsonConvert.DeserializeObject(complete_Input__Text);
            dynamic signatures = complete_Input__Json.signatures;
            dynamic submissions = complete_Input__Json.submissions;
            string filename = "";


            if ((submissions != null) && (submissions[0].filename != null))
            {
                filename = submissions[0].filename;
            }

            if (signatures != null)
            {
                foreach (dynamic next_signature in signatures)
                {
                    //string threat_level = next_signature.threat_level;
                    string mitre_Entry_ID = next_signature.attck_id;
                    if (mitre_Entry_ID != null)
                    {
                        string name = next_signature.name;
                        string identifier = next_signature.identifier;
                        string category = next_signature.category;
                        string description = next_signature.description;
                        string sub_Str = "";
                        List<string> metadata = new List<string>();
                        MITRE_ATTACK_Data__Entry mitre_ATTACK_Data__Entry = null;
                        MITRE_ATTACK_Data__Entry mitre_ATTACK_Data__Parent_Entry = null;
                        MITRE_ATTACK_Data__Entry next_mitre_ATTACK_Data__Repeat_Entry = null;


                        if (MITRE_ATTACK__Data.ContainsKey(mitre_Entry_ID))
                        {
                            mitre_ATTACK_Data__Entry = MITRE_ATTACK__Data[mitre_Entry_ID];
                            if (mitre_ATTACK_Data__Entry != null)
                            {
                                mitre_ATTACK_Data__Entry.entry_Set = true;

                                if (mitre_ATTACK_Data__Entry.repeat_Entry_IDs != null)
                                {
                                    foreach (string next_mitre_ATTACK_Data__Repeat_Entry__ID in mitre_ATTACK_Data__Entry.repeat_Entry_IDs)
                                    {
                                        if (MITRE_ATTACK__Data.ContainsKey(next_mitre_ATTACK_Data__Repeat_Entry__ID))
                                        {
                                            next_mitre_ATTACK_Data__Repeat_Entry = MITRE_ATTACK__Data[next_mitre_ATTACK_Data__Repeat_Entry__ID];
                                            if (next_mitre_ATTACK_Data__Repeat_Entry != null)
                                            {
                                                next_mitre_ATTACK_Data__Repeat_Entry.entry_Set = true;
                                            }
                                        }
                                    }
                                }

                                if (mitre_ATTACK_Data__Entry.parent_Entry_ID != null)
                                {
                                    if (MITRE_ATTACK__Data.ContainsKey(mitre_ATTACK_Data__Entry.parent_Entry_ID))
                                    {
                                        mitre_ATTACK_Data__Parent_Entry = MITRE_ATTACK__Data[mitre_ATTACK_Data__Entry.parent_Entry_ID];
                                        if (mitre_ATTACK_Data__Parent_Entry != null)
                                        {
                                            mitre_ATTACK_Data__Parent_Entry.entry_Set = true;

                                            if (mitre_ATTACK_Data__Parent_Entry.repeat_Entry_IDs != null)
                                            {
                                                foreach (string next_mitre_ATTACK_Data__Repeat_Entry__ID in mitre_ATTACK_Data__Parent_Entry.repeat_Entry_IDs)
                                                {
                                                    if (MITRE_ATTACK__Data.ContainsKey(next_mitre_ATTACK_Data__Repeat_Entry__ID))
                                                    {
                                                        next_mitre_ATTACK_Data__Repeat_Entry = MITRE_ATTACK__Data[next_mitre_ATTACK_Data__Repeat_Entry__ID];
                                                        if (next_mitre_ATTACK_Data__Repeat_Entry != null)
                                                        {
                                                            next_mitre_ATTACK_Data__Repeat_Entry.entry_Set = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            next_metadata_element = "-- Summary:" + name;

                            metadata.Add(next_metadata_element);

                        }
                        else
                        {
                            if (Error_Log != null)
                            {
                                Error_Log.Add("Error - Parsing report - Unknown MITRE Att&ck technique ID   ID=" + mitre_Entry_ID);
                            }
                        }

                        if (identifier.ToLower().Contains("registry"))
                        {
                            int index_00;
                            int index_0;
                            int index_1;
                            bool done;

                            index_00 = 0;
                            done = false;
                            while (!done)
                            {
                                next_metadata_element = null;

                                index_0 = description.ToLower().IndexOf("path: \"", index_00);
                                if (index_0 != -1)
                                {
                                    index_0 += "path: \"".Length;
                                    index_1 = description.ToLower().IndexOf("\"", index_0);
                                    if ((index_1 >= 0) && (index_1 > index_0))
                                    {
                                        sub_Str = description.Substring(index_0, (index_1 - index_0)).Replace("\"", "");

                                        next_metadata_element = "Reg:" + sub_Str;
                                    }

                                    index_00 = index_1 + 1;
                                    if (index_00 >= description.Length)
                                    {
                                        done = true;
                                    }

                                    if (next_metadata_element != null)
                                    {
                                        metadata.Add(next_metadata_element);
                                    }
                                }
                                else
                                {
                                    done = true;
                                }
                            }
                        }

                        if (description.ToLower().Contains("\" wrote"))
                        {
                            int index_00;
                            int index_0;
                            int index_1;
                            bool done;

                            index_00 = 0;
                            done = false;
                            while (!done)
                            {
                                index_0 = description.ToLower().IndexOf("\" wrote", index_00);
                                if (index_0 > 2)
                                {
                                    index_1 = description.ToLower().LastIndexOf("\"", (index_0 - 1));
                                    if ((index_1 >= 0) && (index_0 > index_1))
                                    {
                                        sub_Str = description.Substring(index_1, (index_0 - index_1)).Replace("\"", "");

                                        next_metadata_element = "-- Process Image:" + sub_Str;

                                        metadata.Add(next_metadata_element);
                                    }

                                    index_00 = index_0 + 8;
                                    if (index_00 >= description.Length)
                                    {
                                        done = true;
                                    }
                                }
                                else
                                {
                                    done = true;
                                }
                            }
                        }

                        if ((identifier.ToLower().Contains("network")) || (category.ToLower().Contains("network")))
                        {
                            int index_00;
                            int index_0;
                            int index_1;
                            bool done;

                            index_00 = 0;
                            done = false;
                            while (!done)
                            {
                                next_metadata_element = null;

                                index_0 = description.ToLower().IndexOf("indicator: \"", index_00);
                                if (index_0 != -1)
                                {
                                    index_0 += "indicator: \"".Length;
                                    index_1 = description.ToLower().IndexOf("\"", index_0);
                                    if ((index_1 >= 0) && (index_1 > index_0))
                                    {
                                        sub_Str = description.Substring(index_0, (index_1 - index_0)).Replace("\"", "");

                                        next_metadata_element = "Net:" + sub_Str;
                                    }

                                    index_00 = index_1 + 1;
                                    if (index_00 >= description.Length)
                                    {
                                        done = true;
                                    }

                                    if (next_metadata_element != null)
                                    {
                                        metadata.Add(next_metadata_element);
                                    }
                                }
                                else
                                {
                                    done = true;
                                }
                            }
                        }

                        if (identifier.ToLower().Contains("target"))
                        {
                            int index_00;
                            int index_0;
                            int index_1;
                            int index_2;
                            int index_3;
                            int index_4;
                            bool done;

                            index_00 = 0;
                            done = false;
                            while (!done)
                            {
                                next_metadata_element = null;

                                index_0 = description.ToLower().IndexOf("spawned process \"", index_00);
                                if (index_0 != -1)
                                {
                                    index_0 += "spawned process \"".Length;
                                    index_1 = description.ToLower().IndexOf("\"", index_0);
                                    if ((index_1 >= 0) && (index_1 > index_0))
                                    {
                                        sub_Str = description.Substring(index_0, (index_1 - index_0)).Replace("\"", "");

                                        next_metadata_element = "-- Spawn:" + sub_Str;
                                    }

                                    index_2 = description.ToLower().IndexOf("\" with commandline \"", index_1);
                                    index_3 = description.ToLower().IndexOf("\"spawned process \"", index_1);
                                    if (index_3 == -1)
                                    {
                                        index_3 = description.Length - 1;
                                    }
                                    if ((index_2 > 0) && (index_3 > 0) && (index_2 < index_3))
                                    {
                                        index_2 += "\" with commandline \"".Length;
                                        if (index_2 < description.Length)
                                        {
                                            index_4 = description.ToLower().IndexOf("\"", index_2);
                                            if ((index_4 != -1) && (index_4 > index_2))
                                            {
                                                sub_Str = description.Substring(index_2, (index_4 - index_2));
                                            }

                                            next_metadata_element += " " + sub_Str;

                                            index_00 = index_4 + 1;
                                        }
                                    }
                                    else
                                    {
                                        index_00 = index_1 + 1;
                                    }

                                    if (index_00 >= description.Length)
                                    {
                                        done = true;
                                    }

                                    if (next_metadata_element != null)
                                    {
                                        metadata.Add(next_metadata_element);
                                    }
                                }
                                else
                                {
                                    done = true;
                                }
                            }
                        }

                        // Skipping these for now as they don't add good data
                        //next_metadata_element = "-- Sample:" + sample_name;
                        //metadata.Add(next_metadata_element);

                        //next_metadata_element = "-- Original_name:" + filename;
                        //metadata.Add(next_metadata_element);


                        if (MITRE_ATTACK__Data.ContainsKey(mitre_Entry_ID))
                        {
                            mitre_ATTACK_Data__Entry = MITRE_ATTACK__Data[mitre_Entry_ID];

                            if (mitre_ATTACK_Data__Entry.metadata == null)
                            {
                                mitre_ATTACK_Data__Entry.metadata = new SortedList<string, string>();
                            }

                            if ((mitre_ATTACK_Data__Entry != null) && (mitre_ATTACK_Data__Entry.metadata != null))
                            {
                                foreach (string __next_metadata_element in metadata)
                                {
                                    if (!mitre_ATTACK_Data__Entry.metadata.ContainsKey(__next_metadata_element))
                                    {
                                        mitre_ATTACK_Data__Entry.metadata.Add(__next_metadata_element, "");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        // Write results for submission in human readable text file.
        // 

        private void write_Text_Output(string output_FolderPath, string name)
        {
            string output_FilePath;
            SortedList<int, List<MITRE_ATTACK_Data__Entry>> sorted_Entries;


            // Write error log output
            output_FilePath = output_FolderPath + "\\" + name + "_Error_Log.txt";
            using (StreamWriter streamWriter = new StreamWriter(output_FilePath))
            {
                foreach (string output_Line in Error_Log)
                {
                    streamWriter.WriteLine(output_Line);
                }
            }

            sorted_Entries = new SortedList<int, List<MITRE_ATTACK_Data__Entry>>();
            if (sorted_Entries != null)
            {
                // Write MITRE Att&ck frame hits as text output
                output_FilePath = output_FolderPath + "\\" + name + "_MITRE_Attck_Hits.txt";

                sorted_Entries.Clear();

                using (StreamWriter streamWriter = new StreamWriter(output_FilePath))
                {
                    streamWriter.WriteLine("-- MITRE Att&ck Hits, top techniques");

                    foreach (MITRE_ATTACK_Header__Entry next_MITRE_ATTACK_Header__Entry in MITRE_ATTACK_Headers.Values)
                    {
                        foreach (KeyValuePair<int, List<MITRE_ATTACK_Data__Entry>> kvp in sorted_Entries)
                        {
                            List<MITRE_ATTACK_Data__Entry> entry_List = kvp.Value;

                            if (entry_List != null)
                            {
                                foreach (MITRE_ATTACK_Data__Entry next_sorted_mitre_ATTACK_Data__Entry in entry_List)
                                {
                                    string trimmed_Entry_ID__2;
                                    int trim_Index__2;

                                    trimmed_Entry_ID__2 = next_sorted_mitre_ATTACK_Data__Entry.entry_ID;
                                    trim_Index__2 = trimmed_Entry_ID__2.IndexOf("==");
                                    if (trim_Index__2 != -1)
                                    {
                                        trim_Index__2 += 2;
                                        if (trim_Index__2 < trimmed_Entry_ID__2.Length)
                                        {
                                            trimmed_Entry_ID__2 = trimmed_Entry_ID__2.Substring(trim_Index__2);
                                        }
                                    }

                                    streamWriter.WriteLine("     " + "       " + trimmed_Entry_ID__2);
                                    streamWriter.WriteLine("     " + "       " + next_sorted_mitre_ATTACK_Data__Entry.description);
                                    streamWriter.WriteLine("     " + "       " + "rank:   " + kvp.Key.ToString());
                                    streamWriter.WriteLine("");
                                }
                            }
                        }

                        streamWriter.WriteLine("");
                        streamWriter.WriteLine("");
                        streamWriter.WriteLine("     " + "**Header: " + next_MITRE_ATTACK_Header__Entry.description);

                        sorted_Entries.Clear();

                        foreach (MITRE_ATTACK_Data__Entry next_MITRE_ATTACK_Data__Entry in next_MITRE_ATTACK_Header__Entry.entries.Values)
                        {
                            if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                            {
                                string trimmed_Entry_ID;
                                int trim_Index;

                                trimmed_Entry_ID = next_MITRE_ATTACK_Data__Entry.entry_ID;
                                trim_Index = trimmed_Entry_ID.IndexOf("==");
                                if (trim_Index != -1)
                                {
                                    trim_Index += 2;
                                    if (trim_Index < trimmed_Entry_ID.Length)
                                    {
                                        trimmed_Entry_ID = trimmed_Entry_ID.Substring(trim_Index);
                                    }
                                }

                                if (MITRE_ATTACK_Top_Techniques.ContainsKey(trimmed_Entry_ID))
                                {
                                    MITRE_ATTACK_Top_Techniques__Entry MITRE_ATTACK_Top_Technique;

                                    MITRE_ATTACK_Top_Technique = MITRE_ATTACK_Top_Techniques[trimmed_Entry_ID];

                                    if (MITRE_ATTACK_Top_Technique != null)
                                    {
                                        if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                                        {
                                            List<MITRE_ATTACK_Data__Entry> entry_List;

                                            if (!sorted_Entries.ContainsKey(MITRE_ATTACK_Top_Technique.rank))
                                            {
                                                entry_List = new List<MITRE_ATTACK_Data__Entry>();

                                                if (entry_List != null)
                                                {
                                                    sorted_Entries.Add(MITRE_ATTACK_Top_Technique.rank, entry_List);
                                                }
                                            }
                                            else
                                            {
                                                entry_List = sorted_Entries[MITRE_ATTACK_Top_Technique.rank];
                                            }

                                            if (entry_List != null)
                                            {
                                                entry_List.Add(next_MITRE_ATTACK_Data__Entry);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    streamWriter.WriteLine("");
                    streamWriter.WriteLine("");
                    streamWriter.WriteLine("");
                    streamWriter.WriteLine("");
                    streamWriter.WriteLine("");
                    streamWriter.WriteLine("");

                    streamWriter.WriteLine("-- MITRE Att&ck Hits, remaining tecniques not top priority IDs");

                    foreach (MITRE_ATTACK_Header__Entry next_MITRE_ATTACK_Header__Entry in MITRE_ATTACK_Headers.Values)
                    {
                        streamWriter.WriteLine("");
                        streamWriter.WriteLine("");
                        streamWriter.WriteLine("     " + "**Header: " + next_MITRE_ATTACK_Header__Entry.description);

                        foreach (MITRE_ATTACK_Data__Entry next_MITRE_ATTACK_Data__Entry in next_MITRE_ATTACK_Header__Entry.entries.Values)
                        {
                            if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                            {
                                string trimmed_Entry_ID;
                                int trim_Index;

                                trimmed_Entry_ID = next_MITRE_ATTACK_Data__Entry.entry_ID;
                                trim_Index = trimmed_Entry_ID.IndexOf("==");
                                if (trim_Index != -1)
                                {
                                    trim_Index += 2;
                                    if (trim_Index < trimmed_Entry_ID.Length)
                                    {
                                        trimmed_Entry_ID = trimmed_Entry_ID.Substring(trim_Index);
                                    }
                                }

                                if (!MITRE_ATTACK_Top_Techniques.ContainsKey(trimmed_Entry_ID))
                                {
                                    streamWriter.WriteLine("     " + "     " + trimmed_Entry_ID);
                                    streamWriter.WriteLine("     " + "     " + next_MITRE_ATTACK_Data__Entry.description);
                                    streamWriter.WriteLine("");
                                }
                            }
                        }
                    }
                    streamWriter.WriteLine("");
                    streamWriter.WriteLine("");
                }
            }
        }


        // Write results for submission in csv file.
        // 

        private void write_CSV_Output(string output_FolderPath, string name)
        {
            string output_FilePath;
            bool first_Header;


            output_FilePath = output_FolderPath + "\\" + name + "_MITRE_Attck_Hits.csv";

            using (StreamWriter streamWriter = new StreamWriter(output_FilePath))
            {
                // Write data on techniques used
                streamWriter.WriteLine("Tactic, Techniques Used");     // Write headers for columns

                first_Header = true;

                foreach (MITRE_ATTACK_Header__Entry next_MITRE_ATTACK_Header__Entry in MITRE_ATTACK_Headers.Values)
                {
                    if (first_Header)
                    {
                        first_Header = false;
                    }
                    else
                    {
                        streamWriter.WriteLine("");
                    }
                    streamWriter.Write(next_MITRE_ATTACK_Header__Entry.description);

                    foreach (MITRE_ATTACK_Data__Entry next_MITRE_ATTACK_Data__Entry in next_MITRE_ATTACK_Header__Entry.entries.Values)
                    {
                        if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                        {
                            string trimmed_Entry_ID;
                            int trim_Index;

                            trimmed_Entry_ID = next_MITRE_ATTACK_Data__Entry.entry_ID;
                            trim_Index = trimmed_Entry_ID.IndexOf("==");
                            if (trim_Index != -1)
                            {
                                trim_Index += 2;
                                if (trim_Index < trimmed_Entry_ID.Length)
                                {
                                    trimmed_Entry_ID = trimmed_Entry_ID.Substring(trim_Index);
                                }
                            }

                            streamWriter.Write(", " + trimmed_Entry_ID);
                        }
                    }
                }

                // Write data on techniques used
                streamWriter.WriteLine("");
                streamWriter.WriteLine("");
                streamWriter.WriteLine("Technique,");     // Write headers for columns

                foreach (MITRE_ATTACK_Data__Entry next_MITRE_ATTACK_Data__Entry in MITRE_ATTACK__Data.Values)
                {
                    if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                    {
                        streamWriter.Write(next_MITRE_ATTACK_Data__Entry.entry_ID);

                        if ((next_MITRE_ATTACK_Data__Entry.metadata != null) && (next_MITRE_ATTACK_Data__Entry.metadata.Count > 0))
                        {
                            foreach (string __next_metadata_element in next_MITRE_ATTACK_Data__Entry.metadata.Keys)
                            {
                                streamWriter.Write("," + __next_metadata_element);
                            }
                        }
                        streamWriter.WriteLine();
                    }
                }
            }
        }


        // Write results for submission as graphical file.
        // 

        private void draw_Images(string output_FolderPath, string name, bool include_SubTechniques)
        {
            string output_FilePath;
            Font font = new Font("Arial", 14);
            int next_Box__x;
            int next_Box__y;
            bool first_Header;
            bool top_Technique;
            Rectangle drawRectangle;


            if (font != null)
            {
                // Create and write image for hits against complete list of Att&ck techniques
                output_FilePath = output_FolderPath + "\\" + name + "_Hits__Complete_List.png";

                using (var image = new Bitmap(attck_Matrix_Image__width, attck_Matrix_Image__height))
                {
                    using (var graphics = Graphics.FromImage(image))
                    {
                        next_Box__x = 0;
                        next_Box__y = 0;
                        first_Header = true;

                        //foreach (MITRE_ATTACK_Data__Entry next_mitre_ATTACK_Data__Entry in MITRE_ATTACK__Data.Values)
                        foreach (MITRE_ATTACK_Header__Entry next_MITRE_ATTACK_Header__Entry in MITRE_ATTACK_Headers.Values)
                        {
                            if (first_Header)
                            {
                                first_Header = false;
                            }
                            else
                            {
                                next_Box__x += (attck_Matrix_Image__box_width + (2 * attck_Matrix_Image__box_offset_x));
                                next_Box__y = 0;
                            }

                            drawRectangle = new Rectangle(next_Box__x + attck_Matrix_Image__box_text_x, next_Box__y + attck_Matrix_Image__box_text_y, attck_Matrix_Image__box_width - (2 * attck_Matrix_Image__box_text_x), attck_Matrix_Image__box_height - (2 * attck_Matrix_Image__box_text_y));

                            if (drawRectangle != null)
                            {
                                graphics.FillRectangle(Brushes.DarkSlateBlue, next_Box__x, next_Box__y, attck_Matrix_Image__box_width, attck_Matrix_Image__box_height);
                                graphics.DrawString(next_MITRE_ATTACK_Header__Entry.description, font, Brushes.AntiqueWhite, drawRectangle, StringFormat.GenericDefault);
                            }

                            foreach (KeyValuePair<string, MITRE_ATTACK_Data__Entry> kvp in next_MITRE_ATTACK_Header__Entry.entries)
                            {
                                MITRE_ATTACK_Data__Entry next_MITRE_ATTACK_Data__Entry;


                                next_MITRE_ATTACK_Data__Entry = kvp.Value;
                                if (next_MITRE_ATTACK_Data__Entry != null)
                                {
                                    if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                                    {
                                        Brush brush;
                                        int indent;
                                        string trimmed_Entry_ID;
                                        int trim_Index;

                                        trimmed_Entry_ID = next_MITRE_ATTACK_Data__Entry.entry_ID;
                                        trim_Index = trimmed_Entry_ID.IndexOf("==");
                                        if (trim_Index != -1)
                                        {
                                            trim_Index += 2;
                                            if (trim_Index < trimmed_Entry_ID.Length)
                                            {
                                                trimmed_Entry_ID = trimmed_Entry_ID.Substring(trim_Index);
                                            }
                                        }

                                        top_Technique = false;
                                        if (MITRE_ATTACK_Top_Techniques.ContainsKey(trimmed_Entry_ID))
                                        {
                                            MITRE_ATTACK_Top_Techniques__Entry MITRE_ATTACK_Top_Technique;

                                            MITRE_ATTACK_Top_Technique = MITRE_ATTACK_Top_Techniques[trimmed_Entry_ID];
                                            if (MITRE_ATTACK_Top_Technique != null)
                                            {
                                                top_Technique = true;
                                            }
                                        }

                                        if (include_SubTechniques || (next_MITRE_ATTACK_Data__Entry.parent_Entry_ID == null))
                                        {
                                            if (next_MITRE_ATTACK_Data__Entry.parent_Entry_ID == null)
                                            {
                                                brush = Brushes.DarkGreen;
                                                indent = 0;
                                            }
                                            else
                                            {
                                                brush = Brushes.DarkMagenta;
                                                indent = attck_Matrix_Image__box_offset_x;
                                            }

                                            next_Box__y += (attck_Matrix_Image__box_height + attck_Matrix_Image__box_offset_y);

                                            drawRectangle = new Rectangle(next_Box__x + indent + attck_Matrix_Image__box_text_x, next_Box__y + attck_Matrix_Image__box_text_y, attck_Matrix_Image__box_width - (2 * attck_Matrix_Image__box_text_x), attck_Matrix_Image__box_height - (2 * attck_Matrix_Image__box_text_y));

                                            if (drawRectangle != null)
                                            {
                                                graphics.FillRectangle(brush, next_Box__x + indent, next_Box__y, attck_Matrix_Image__box_width, attck_Matrix_Image__box_height);
                                                graphics.DrawString(next_MITRE_ATTACK_Data__Entry.description, font, Brushes.AntiqueWhite, drawRectangle, StringFormat.GenericDefault);
                                            }

                                            if (top_Technique)
                                            {
                                                graphics.FillRectangle(Brushes.Black, next_Box__x + indent, next_Box__y, attck_Matrix_Image__top_technique__box_width, attck_Matrix_Image__box_height);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    image.Save(output_FilePath, System.Drawing.Imaging.ImageFormat.Png);
                }
            }
        }

        public void write_Output(string output_FolderPath, string name, bool include_SubTechniques)
        {

            write_Text_Output(output_FolderPath, name);
            write_CSV_Output(output_FolderPath, name);
            draw_Images(output_FolderPath, name, include_SubTechniques);
        }


        // Collate the csv file results from processing individual submissions, produces an ATT&CK layer file for import into ATT&CK Navigator.
        // 

        public void Collate_Individual_Sandbox_Report(string input_FilePath)
        {
            string next_Input_Line;
            char[] char_Separators = new char[] { ',' };
            string[] split_Input_Line;
            int input_Line_Count;
            MITRE_ATTACK_Data__Entry mitre_ATTACK_Data__Entry;
            bool done_Reading_Section;


            using (StreamReader streamReader = new StreamReader(input_FilePath))
            {
                input_Line_Count = 0;


                // Read in lines with data on techniques cited in report
                done_Reading_Section = false;
                streamReader.ReadLine();    // Skip first line, has column names
                while (!streamReader.EndOfStream && !done_Reading_Section)
                {
                    next_Input_Line = streamReader.ReadLine();
                    input_Line_Count++;

                    if (next_Input_Line.Length < 1)
                    {
                        done_Reading_Section = true;
                    }
                    else
                    {
                        next_Input_Line = next_Input_Line.Replace(" ", "");
                        split_Input_Line = next_Input_Line.Split(char_Separators, StringSplitOptions.None);
                        if (split_Input_Line.Length > 1)
                        {
                            for (int i = 1; i < split_Input_Line.Length; i++)
                            {
                                if (MITRE_ATTACK__Data.ContainsKey(split_Input_Line[i]))
                                {
                                    mitre_ATTACK_Data__Entry = MITRE_ATTACK__Data[split_Input_Line[i]];
                                    if (mitre_ATTACK_Data__Entry != null)
                                    {
                                        mitre_ATTACK_Data__Entry.hit_Count++;

                                        total_Techniques_Hit++;
                                    }
                                }
                            }
                        }
                    }
                }

                // Next, read in lines with meta data included in report for cited techniques
                // Skip to start of section's data
                done_Reading_Section = false;
                while (!streamReader.EndOfStream && !done_Reading_Section)
                {
                    next_Input_Line = streamReader.ReadLine();
                    input_Line_Count++;

                    if (next_Input_Line.ToLower().Contains("technique"))
                    {
                        done_Reading_Section = true;
                    }
                }

                // Read section's data
                while (!streamReader.EndOfStream)
                {
                    next_Input_Line = streamReader.ReadLine();
                    input_Line_Count++;

                    //next_Input_Line = next_Input_Line.Replace(" ", "");
                    split_Input_Line = next_Input_Line.Split(char_Separators, StringSplitOptions.None);
                    if (split_Input_Line.Length > 1)
                    {
                        if (MITRE_ATTACK__Data.ContainsKey(split_Input_Line[0]))
                        {
                            mitre_ATTACK_Data__Entry = MITRE_ATTACK__Data[split_Input_Line[0]];
                            if (mitre_ATTACK_Data__Entry != null)
                            {
                                for (int i = 1; i < split_Input_Line.Length; i++)
                                {
                                    if (mitre_ATTACK_Data__Entry.metadata == null)
                                    {
                                        mitre_ATTACK_Data__Entry.metadata = new SortedList<string, string>();
                                    }
                                    if (!mitre_ATTACK_Data__Entry.metadata.ContainsKey(split_Input_Line[i]))
                                    {
                                        mitre_ATTACK_Data__Entry.metadata.Add(split_Input_Line[i], "");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public void Collate_Sandbox_Reports(string input_FilePath)
        {
            var csv_Files = Directory.EnumerateFiles(input_FilePath, "*.csv", SearchOption.TopDirectoryOnly);


            total_Techniques_Hit = 0;

            foreach (string next_Filepath in csv_Files)
            {
                Collate_Individual_Sandbox_Report(next_Filepath);
            }
        }


        // Write collated output as Navigator layer file.
        // 

        public void write_Collated_Output(string output_FolderPath, string name, bool include_SubTechniques)
        {
            string output_FilePath;
            bool first_Entry;
            bool first_Entry__2;
            int score;
            string description;
            char[] char_Separators = new char[] { ':' };
            string[] split_metadata;
            string metadata_name;
            string metadata_value;


            output_FilePath = output_FolderPath + "\\" + name + "_MITRE_Attck_Heatmap.json";

            using (StreamWriter streamWriter = new StreamWriter(output_FilePath))
            {
                streamWriter.WriteLine("{");
                streamWriter.WriteLine("    \"name\": " + "\"" + name + "\"" + ",");
                streamWriter.WriteLine("    \"version\": " + "\"3.0\"" + ",");
                streamWriter.WriteLine("    \"domain\": " + "\"mitre-enterprise\"" + ",");
                streamWriter.WriteLine("    \"description\": " + "\"Collated Sandbox report data\"" + ",");
                streamWriter.WriteLine("    \"filters\": {");
                streamWriter.WriteLine("        \"stages\": [");
                streamWriter.WriteLine("            \"act\"");
                streamWriter.WriteLine("        ],");
                streamWriter.WriteLine("        \"platforms\": [");
                streamWriter.WriteLine("            \"Windows\",");
                streamWriter.WriteLine("            \"Linux\",");
                streamWriter.WriteLine("            \"macOS\"");
                streamWriter.WriteLine("        ]");
                streamWriter.WriteLine("    },");
                streamWriter.WriteLine("    \"sorting\": " + "3" + ",");
                streamWriter.WriteLine("    \"layout\": {");
                streamWriter.WriteLine("        \"layout\": " + "\"side\"" + ",");
                streamWriter.WriteLine("        \"showID\": " + "true" + ",");
                streamWriter.WriteLine("        \"showName\": " + "true");
                streamWriter.WriteLine("    },");
                streamWriter.WriteLine("    \"hideDisabled\": " + "false" + ",");
                streamWriter.WriteLine("    \"techniques\": " + "[");

                first_Entry = true;

                foreach (MITRE_ATTACK_Header__Entry next_MITRE_ATTACK_Header__Entry in MITRE_ATTACK_Headers.Values)
                {
                    foreach (MITRE_ATTACK_Data__Entry next_MITRE_ATTACK_Data__Entry in next_MITRE_ATTACK_Header__Entry.entries.Values)
                    {
                        if (next_MITRE_ATTACK_Data__Entry.hit_Count > 0)
                        {
                            string trimmed_Entry_ID;
                            int trim_Index;

                            if (first_Entry)
                            {
                                first_Entry = false;
                            }
                            else
                            {
                                streamWriter.WriteLine(",");
                            }

                            trimmed_Entry_ID = next_MITRE_ATTACK_Data__Entry.entry_ID;
                            trim_Index = trimmed_Entry_ID.IndexOf("==");
                            if (trim_Index != -1)
                            {
                                trim_Index += 2;
                                if (trim_Index < trimmed_Entry_ID.Length)
                                {
                                    trimmed_Entry_ID = trimmed_Entry_ID.Substring(trim_Index);
                                }
                            }

                            description = next_MITRE_ATTACK_Header__Entry.description.ToLower().Replace(" ", "-");

                            // Calculate raw score (independent of technique ranking)
                            score = attck_Navigator_Heatmap_Max_score - ((next_MITRE_ATTACK_Data__Entry.hit_Count * attck_Navigator_Heatmap_Max_score) / total_Techniques_Hit);

                            // Re-calculate raw score with ranking
                            if (MITRE_ATTACK_Top_Techniques.ContainsKey(trimmed_Entry_ID))
                            {
                                MITRE_ATTACK_Top_Techniques__Entry mitre_ATTACK_Top_Techniques__Entry;

                                mitre_ATTACK_Top_Techniques__Entry = MITRE_ATTACK_Top_Techniques[trimmed_Entry_ID];
                                if ((mitre_ATTACK_Top_Techniques__Entry != null) && (mitre_ATTACK_Top_Techniques__Entry.rank <= attck_Navigator_Ranking__High_Threshold))
                                {
                                    score = (score * attck_Navigator_Heatmap_Max_score__High_Ranking) / attck_Navigator_Heatmap_Max_score;
                                }
                                else if ((mitre_ATTACK_Top_Techniques__Entry != null) && (mitre_ATTACK_Top_Techniques__Entry.rank <= attck_Navigator_Ranking__Medium_Threshold))
                                {
                                    score = (score * attck_Navigator_Heatmap_Max_score__Medium_Ranking) / attck_Navigator_Heatmap_Max_score;
                                }
                                else
                                {
                                    score = (score * attck_Navigator_Heatmap_Max_score__Low_Ranking) / attck_Navigator_Heatmap_Max_score;
                                }
                            }

                            streamWriter.WriteLine("        {");
                            streamWriter.WriteLine("            \"techniqueID\": " + "\"" + trimmed_Entry_ID + "\",");
                            streamWriter.WriteLine("            \"tactic\": " + "\"" + description + "\",");
                            streamWriter.WriteLine("            \"score\": " + score + ",");
                            streamWriter.WriteLine("            \"color\": " + "\"\"" + ",");
                            streamWriter.WriteLine("            \"comment\": " + "\"\"" + ",");
                            //if (next_MITRE_ATTACK_Data__Entry.entry_Set)
                            //{
                            //    streamWriter.WriteLine("            \"enabled\": " + "true" + ",");
                            //}
                            //else
                            //{
                            //    streamWriter.WriteLine("            \"enabled\": " + "false" + ",");
                            //}
                            streamWriter.WriteLine("            \"enabled\": " + "true" + ",");

                            if (next_MITRE_ATTACK_Data__Entry.metadata != null)
                            {
                                streamWriter.WriteLine("            \"metadata\": " + "[");

                                first_Entry__2 = true;
                                foreach (string __next_metadata_element in next_MITRE_ATTACK_Data__Entry.metadata.Keys)
                                {
                                    split_metadata = __next_metadata_element.Split(char_Separators);
                                    if (split_metadata.Length >= 2)
                                    {
                                        metadata_name = split_metadata[0];
                                        metadata_value = split_metadata[1].Replace("\\", "\\\\");
                                    }
                                    else
                                    {
                                        metadata_name = "";
                                        metadata_value = "";
                                    }

                                    if (first_Entry__2)
                                    {
                                        first_Entry__2 = false;
                                    }
                                    else
                                    {
                                        streamWriter.WriteLine(",");
                                    }

                                    streamWriter.WriteLine("                {");
                                    streamWriter.WriteLine("                    \"name\": " + "\"" + metadata_name + "\",");
                                    streamWriter.WriteLine("                    \"value\": " + "\"" + metadata_value + "\"");
                                    streamWriter.Write("                }");
                                }

                                streamWriter.WriteLine();
                                streamWriter.WriteLine("            ]" + ",");
                            }
                            else
                            {
                                streamWriter.WriteLine("            \"metadata\": " + "[],");
                            }

                            if (include_SubTechniques)
                            {
                                streamWriter.WriteLine("            \"showSubtechniques\": " + "true");
                            }
                            else
                            {
                                streamWriter.WriteLine("            \"showSubtechniques\": " + "false");
                            }
                            streamWriter.Write("        }");
                        }
                    }
                }

                streamWriter.WriteLine();

                streamWriter.WriteLine("    ],");
                streamWriter.WriteLine("    \"gradient\": {");
                streamWriter.WriteLine("        \"colors\": [");
                streamWriter.WriteLine("            \"#ff6666\",");
                streamWriter.WriteLine("            \"#ffe766\",");
                streamWriter.WriteLine("            \"#8ec843\"");
                streamWriter.WriteLine("        ],");
                streamWriter.WriteLine("        \"minValue\": " + "0,");
                streamWriter.WriteLine("        \"maxValue\": " + "100");
                streamWriter.WriteLine("    },");
                streamWriter.WriteLine("    \"legendItems\": [],");
                streamWriter.WriteLine("    \"metadata\": [],");
                streamWriter.WriteLine("    \"showTacticRowBackground\": " + "false" + ",");
                streamWriter.WriteLine("    \"tacticRowBackground\": " + "\"#dddddd\"" + ", ");
                streamWriter.WriteLine("    \"selectTechniquesAcrossTactics\": " + "true" + ",");
                streamWriter.WriteLine("    \"selectSubtechniquesWithParent\": " + "true");
                streamWriter.WriteLine("}");
            }
        }
    }


    class Program
    {
        static void Main(string[] args)
        {
            Run_Sandbox_Scryer_Command run_Sandbox_Scryer_Command = null;
            bool showUsage = false;
            bool should_Run_Tool = true;
            int index_Increment = 0;
            string input_FilePath = "";
            string input_FilePath__TOP_Techniques = "";
            string output_FolderPath = "";
            string file_type = "";
            string name = "";
            string sb_name = "";
            string api_key = "";
            string environment_ID = "";
            string mitre_init_Data_Filepath = "";
            bool include_SubTechniques = false;
            string command = "";


            // Notes on general flow and usage:
            //
            // The tool is driven by command-line parameters, centered around the 'cmd' parameter which determines what actions are being taken for an invocation of the tool.
            //
            // At present, the 'sub' command is not implemented.  Also, only Sandbox reports in xml format are supported.
            //

            Console.WriteLine("Sandbox Scryer");

            if (args.Length > 0)
            {
                if (args[0].ToLower() == "-h")
                {
                    showUsage = true;
                    should_Run_Tool = false;
                }
                else
                {
                    should_Run_Tool = true;
                    for (int arg_Index = 0; arg_Index < args.Length; arg_Index += index_Increment)
                    {
                        index_Increment = 1;

                        if (args[arg_Index].ToLower() == "-i")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                input_FilePath = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-ita")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                input_FilePath__TOP_Techniques = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-o")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                output_FolderPath = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-ft")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                file_type = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-name")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                name = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-sb_name")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                sb_name = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-api_key")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                api_key = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-env_id")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                environment_ID = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-inc_sub")
                        {
                            include_SubTechniques = true;
                        }
                        else if (args[arg_Index].ToLower() == "-mitre_data")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                mitre_init_Data_Filepath = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                        else if (args[arg_Index].ToLower() == "-cmd")
                        {
                            if ((arg_Index + 1) < args.Length)
                            {
                                command = args[arg_Index + 1];
                                index_Increment = 2;
                            }
                        }
                    }
                }
            }

            if (showUsage)
            {
                Console.WriteLine("Sandbox_Scryer.exe");
                Console.WriteLine("   Options:");
                Console.WriteLine("      -h  Display command-line options");
                Console.WriteLine("      -i  Input filepath");
                Console.WriteLine("      -ita  Input filepath - MITRE report for top techniques");
                Console.WriteLine("      -o  Output folder path");
                Console.WriteLine("      -ft Type of file to submit");
                Console.WriteLine("      -name Name to use with output");
                Console.WriteLine("      -sb_name Identifier of sandbox to use  (default:  ha)");
                Console.WriteLine("      -api_key API key to use with submission to sandbox");
                Console.WriteLine("      -env_id Environment ID to use with submission to sandbox");
                Console.WriteLine("      -inc_sub Include sub-techniques in graphical output  (default is to not include)");
                Console.WriteLine("      -mitre_data Filepath for mitre cti data to parse (to populate att&ck techniques)");
                Console.WriteLine("      -cmd  Command");
                Console.WriteLine("            Options:");
                // Currently not implemented
                //Console.WriteLine("               sub    Submit sample to sandbox and processes resulting report file");
                //Console.WriteLine("                      Uses -i, -ita, -o, -ft, -name, -sb_name, -api_key, -env_id, -inc_sub, -mitre_data   parameters");
                //
                Console.WriteLine("               parse  Process report file from prior sandbox submission");
                Console.WriteLine("                      Uses -i, -ita, -o, -name, -inc_sub, -sig_data   parameters");
                Console.WriteLine("               col    Collates report data from prior sandbox submissions");
                Console.WriteLine("                      Uses -i (treated as folder path), -ita, -o, -name, -inc_sub, -mitre_data   parameters"); Console.WriteLine();
            }
            else if (should_Run_Tool)
            {
                run_Sandbox_Scryer_Command = new Run_Sandbox_Scryer_Command();
                if (run_Sandbox_Scryer_Command != null)
                {
                    if (command.ToLower() == "sub")
                    {
                        // Currently not implemented
                        //run_Sandbox_Scryer_Command.init_Data(input_FilePath__TOP_Techniques, mitre_init_Data_Filepath);
                        //run_Sandbox_Scryer_Command.Submit_Sample(input_FilePath, file_type, sb_name, api_key, environment_ID);
                        //run_Sandbox_Scryer_Command.write_Output(output_FolderPath, name, include_SubTechniques);
                    }
                    else if (command.ToLower() == "parse")
                    {
                        run_Sandbox_Scryer_Command.init_Data(input_FilePath__TOP_Techniques, mitre_init_Data_Filepath);
                        //run_Sandbox_Scryer_Command.Parse_Sandbox_Report(input_FilePath);
                        run_Sandbox_Scryer_Command.Parse_Sandbox_Report_Summary(input_FilePath);
                        run_Sandbox_Scryer_Command.write_Output(output_FolderPath, name, include_SubTechniques);
                    }
                    else if (command.ToLower() == "col")
                    {
                        run_Sandbox_Scryer_Command.init_Data(input_FilePath__TOP_Techniques, mitre_init_Data_Filepath);
                        run_Sandbox_Scryer_Command.Collate_Sandbox_Reports(input_FilePath);
                        run_Sandbox_Scryer_Command.write_Collated_Output(output_FolderPath, name, include_SubTechniques);
                    }
                }
            }
        }
    }
}
