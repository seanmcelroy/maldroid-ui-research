/*
 * This file is an artifact of the research publication "Identifying Android
 * Banking Malware through Measurement of User Interface Complexity"
 * Copyright (c) 2023 Sean A. McElroy
 * Authors: Sean A. McElroy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * any later version.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving this software without
 * disclosing the source code of your own applications. *
 */
 
using System.Collections.Generic;
using System.Linq;

namespace droid_res_parser
{
    class ProjectMetric
    {
        public string Folder;
        public int XmlAnimFileCount;
        public int XmlColorFileCount;
        public int XmlFontFileCount;
        public int XmlInterpolatorFileCount;
        public int XmlDrawableFileCount;
        public int XmlTransitionFileCount;
        public int DrawableDensityFolderCount;
        public int ValueLocaleFolderCount;
        public Dictionary<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)> Layouts = new Dictionary<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>();
        //public Dictionary<string, HashSet<string>> OtherXmls = new Dictionary<string, HashSet<string>>();
        public HashSet<string> StringKeys = new HashSet<string>();
        public HashSet<string> StyleKeys = new HashSet<string>();

        public static string CsvHeader() => $"\"{nameof(Folder)}\",\"Malicious\",\"{nameof(XmlAnimFileCount)}\",\"{nameof(XmlColorFileCount)}\",\"{nameof(XmlFontFileCount)}\",\"{nameof(XmlInterpolatorFileCount)}\",\"{nameof(XmlDrawableFileCount)}\",\"{nameof(XmlTransitionFileCount)}\",\"LayoutCount\",\"LayoutAvgMaxDepth\",\"LayoutMaxDepth\",\"LayoutAvgElementCount\",\"LayoutTotalElementCount\",\"LayoutAvgAttributeCount\",\"LayoutTotalAttributeCount\",\"StringCount\",\"StyleCount\",\"{nameof(DrawableDensityFolderCount)}\",\"{nameof(ValueLocaleFolderCount)}\"";//,\"UnusedStrings\",\"UnusedStringPct\"";
        public string ToCsvRow(int malicious)
        {
            double layoutAvgMaxDepth = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>)).Average(l => l.Value.maxDepth);
            int layoutMaxDepth = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>)).Max(l => l.Value.maxDepth);
            double layoutAvgElementCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>)).Average(l => l.Value.elementCount);
            int layoutTotalElementCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>)).Sum(l => l.Value.elementCount);
            double layoutAvgAttributeCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>)).Average(l => l.Value.attributeCount);
            int layoutTotalAttributeCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount, HashSet<string> stringRefs)>)).Sum(l => l.Value.attributeCount);
            /*int unusedStrings = StringKeys
                .Where(x => string.Compare(x, "app_name") != 0)
                .Where(x => !x.StartsWith("abc_"))
                .Where(x => !x.StartsWith("auth_google_play_services_client_"))
                .Where(x => !x.StartsWith("common_google_play_services"))
                .Except(Layouts.SelectMany(l => l.Value.stringRefs))
                .Except(OtherXmls.SelectMany(l => l.Value))
                .Count();
            float unusedStringPct = (float)unusedStrings / (float)StringKeys.Count;*/

            return $"\"{Folder}\",{malicious},{XmlAnimFileCount},{XmlColorFileCount},{XmlFontFileCount},{XmlInterpolatorFileCount},{XmlDrawableFileCount},{XmlTransitionFileCount},{Layouts.Count},{layoutAvgMaxDepth:N1},{layoutMaxDepth},{layoutAvgElementCount:N1},{layoutTotalElementCount},{layoutAvgAttributeCount:N1},{layoutTotalAttributeCount},{StringKeys.Count},{StyleKeys.Count},{DrawableDensityFolderCount},{ValueLocaleFolderCount}";//,{unusedStrings},{unusedStringPct}";
        }
    }
}