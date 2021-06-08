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
        public Dictionary<string, (int maxDepth, int elementCount, int attributeCount)> Layouts = new Dictionary<string, (int maxDepth, int elementCount, int attributeCount)>();
        public HashSet<string> StringKeys = new HashSet<string>();
        public HashSet<string> StyleKeys = new HashSet<string>();

        public static string CsvHeader() => $"\"{nameof(Folder)}\",\"{nameof(XmlAnimFileCount)}\",\"{nameof(XmlColorFileCount)}\",\"{nameof(XmlFontFileCount)}\",\"{nameof(XmlInterpolatorFileCount)}\",\"{nameof(XmlDrawableFileCount)}\",\"{nameof(XmlTransitionFileCount)}\",\"LayoutCount\",\"LayoutAvgMaxDepth\",\"LayoutMaxDepth\",\"LayoutAvgElementCount\",\"LayoutTotalElementCount\",\"LayoutAvgAttributeCount\",\"LayoutTotalAttributeCount\",\"StringCount\",\"StyleCount\",\"{nameof(DrawableDensityFolderCount)}\",\"{nameof(ValueLocaleFolderCount)}\"";
        public string ToCsvRow()
        {
            double layoutAvgMaxDepth = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount)>)).Average(l => l.Value.maxDepth);
            int layoutMaxDepth = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount)>)).Max(l => l.Value.maxDepth);
            double layoutAvgElementCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount)>)).Average(l => l.Value.elementCount);
            int layoutTotalElementCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount)>)).Sum(l => l.Value.elementCount);
            double layoutAvgAttributeCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount)>)).Average(l => l.Value.attributeCount);
            int layoutTotalAttributeCount = Layouts.DefaultIfEmpty(default(KeyValuePair<string, (int maxDepth, int elementCount, int attributeCount)>)).Sum(l => l.Value.attributeCount);
            
            return $"\"{Folder}\",{XmlAnimFileCount},{XmlColorFileCount},{XmlFontFileCount},{XmlInterpolatorFileCount},{XmlDrawableFileCount},{XmlTransitionFileCount},{Layouts.Count},{layoutAvgMaxDepth:N1},{layoutMaxDepth},{layoutAvgElementCount:N1},{layoutTotalElementCount},{layoutAvgAttributeCount:N1},{layoutTotalAttributeCount},{StringKeys.Count},{StyleKeys.Count},{DrawableDensityFolderCount},{ValueLocaleFolderCount}";
        }
    }
}