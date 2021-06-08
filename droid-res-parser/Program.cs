using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;

namespace droid_res_parser
{
    class Program
    {
        private static int projectCount;

        private const int maxProjects = int.MaxValue;

        private static List<ProjectMetric> metrics = new List<ProjectMetric>();

        static async Task Main(string[] args)
        {
            Console.WriteLine("Android Resource Parser and Analyzer");

            const string inputPath = "/Users/smcelroy/Downloads/Benign";
            const string outputPath = "/Users/smcelroy/Downloads/Benign.csv";

            RecursivelyDo(null, inputPath, "*.xml", ParseXml);

            Console.WriteLine($"Projects analyzed: {projectCount}");

            Console.WriteLine($"Metrics collected: {metrics.Count}");

            using (var sw = new StreamWriter(outputPath))
            {
                //Console.Out.WriteLine(ProjectMetric.CsvHeader());
                await sw.WriteLineAsync(ProjectMetric.CsvHeader());
                foreach (var metric in metrics)
                {
                    //Console.Out.WriteLine(metric.ToCsvRow());
                    await sw.WriteLineAsync(metric.ToCsvRow());
                }
            }
        }

        static void RecursivelyDo(
            string basePath,
            string currentPath,
            string filePattern,
            Func<string, string, int, ProjectMetric, ProjectMetric> action,
            int depth = 0,
            ProjectMetric projectMetric = null)
        {
            var actualBase = depth == 1 ? currentPath : basePath;
            if (depth == 1)
            {
                Console.WriteLine($"dir {currentPath}");
                projectCount++;
                if (projectCount > maxProjects)
                    return;

                var eo = new EnumerationOptions
                {
                    MatchType = MatchType.Simple,
                    IgnoreInaccessible = true
                };

                int drawableDensityFolderCount;
                try
                {
                    drawableDensityFolderCount = Directory.GetDirectories(currentPath, $"res/drawable-*", eo).Length;
                }
                catch (DirectoryNotFoundException)
                {
                    drawableDensityFolderCount = 0;
                }

                int valueLocaleFolderCount;
                try
                {
                    valueLocaleFolderCount = Directory.GetDirectories(currentPath, $"res/values-??", eo).Length;
                }
                catch (DirectoryNotFoundException)
                {
                    valueLocaleFolderCount = 0;
                }

                projectMetric = new ProjectMetric
                {
                    Folder = actualBase,
                    DrawableDensityFolderCount = drawableDensityFolderCount,
                    ValueLocaleFolderCount = valueLocaleFolderCount
                };
            }

            // Depth-first
            foreach (var subdir in Directory.GetDirectories(currentPath))
            {
                RecursivelyDo(actualBase, subdir, filePattern, action, depth + 1, projectMetric);
            }

            foreach (var file in Directory.GetFiles(currentPath, filePattern))
            {
                if (!file.EndsWith("AndroidManifest.xml", StringComparison.OrdinalIgnoreCase)
                    && !file.Contains("/unknown/", StringComparison.OrdinalIgnoreCase))
                    projectMetric = action.Invoke(actualBase, file, depth + 1, projectMetric);
            }

            if (depth == 1)
            {
                metrics.Add(projectMetric);
            }
        }

        static ProjectMetric ParseXml(string basePath, string filePath, int depth, ProjectMetric projectMetric)
        {
            var filename = Path.GetFileName(filePath);

            var doc = new XmlDocument();
            try
            {
                doc.Load(filePath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR {filePath}: {ex.Message}".PadLeft(depth, '.'));
                return projectMetric;
            }

            if (string.Compare(doc.DocumentElement.Name, "menu") == 0)
            {
                //Console.WriteLine(" menu ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc.DocumentElement.Name, "device-admin") == 0)
            {
                //Console.WriteLine(" device-admin ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc.DocumentElement.Name, "rotate") == 0)
            {
                //Console.WriteLine(" rotate ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc.DocumentElement.Name, "selector") == 0)
            {
                //Console.WriteLine(" selector ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc.DocumentElement.Name, "shape") == 0)
            {
                //Console.WriteLine(" shape ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc.DocumentElement.Name, "vector") == 0)
            {
                //Console.WriteLine(" vector ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains("/res/layout")
                && filePath.EndsWith(".xml")
                /*&& (
                    doc.DocumentElement.Name.Contains("Layout")
                    || doc.DocumentElement.Name.Contains("android.support.v7.widget.SwitchCompat") // Never seen in Banking?
                    || doc.DocumentElement.Name.Contains("android.support.v7.widget.Toolbar")
                    || doc.DocumentElement.Name.Contains("Button")
                    || doc.DocumentElement.Name.Contains("CheckBox")
                    || doc.DocumentElement.Name.Contains("Chronometer")
                    || doc.DocumentElement.Name.Contains("com.googlecode.android.widgets.DateSlider.SliderContainer") // Never seen in Banking?
                    || doc.DocumentElement.Name.Contains("EditText")
                    || doc.DocumentElement.Name.Contains("fragment") // Never seen in Banking?
                    || doc.DocumentElement.Name.Contains("merge")
                    || doc.DocumentElement.Name.Contains("PreferenceScreen") // Never seen in Banking?
                    || doc.DocumentElement.Name.Contains("ProgressBar")
                    || doc.DocumentElement.Name.Contains("RadioGroup")
                    || doc.DocumentElement.Name.Contains("RatingBar")
                    || doc.DocumentElement.Name.Contains("SeekBar")
                    || doc.DocumentElement.Name.Contains("DatePicker")
                    || doc.DocumentElement.Name.Contains("TimePicker")
                    || doc.DocumentElement.Name.Contains("Space")
                    || doc.DocumentElement.Name.Contains("Switch")
                    || doc.DocumentElement.Name.Contains("TabHost")
                    || doc.DocumentElement.Name.Contains("TableRow")
                    || doc.DocumentElement.Name.Contains("layer-list")
                    || doc.DocumentElement.Name.Contains("view")
                    || doc.DocumentElement.Name.Contains("View")
                )*/
                )
            {
                //Console.WriteLine(" layout XML file ".PadLeft(depth, '.'));

                var maxDepth = doc.DocumentElement.MaxDepth();
                var elementCount = doc.DocumentElement.ElementCount();
                var attributeCount = doc.DocumentElement.AttributeCount();
                projectMetric.Layouts.Add(filePath, (maxDepth, elementCount, attributeCount));
            }
            else if (
                filePath.Contains("/res/xml")
                && filePath.EndsWith(".xml")
                )
            {
                Console.WriteLine(" embedded other XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains("/res/")
                && filePath.EndsWith("/dimens.xml")
                && string.Compare(doc.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" 'dimens' XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains("/res/")
                && filePath.EndsWith("/arrays.xml")
                && string.Compare(doc.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" array XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains("/res/anim")
                && filePath.EndsWith(".xml")
                /*&& (
                    string.Compare(doc.DocumentElement.Name, "alpha") == 0
                    || string.Compare(doc.DocumentElement.Name, "accelerateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "animated-rotate") == 0
                    || string.Compare(doc.DocumentElement.Name, "animation-list") == 0
                    || string.Compare(doc.DocumentElement.Name, "cycleInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "decelerateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "gridLayoutAnimation") == 0
                    || string.Compare(doc.DocumentElement.Name, "layoutAnimation") == 0
                    || string.Compare(doc.DocumentElement.Name, "LinearLayout") == 0
                    || string.Compare(doc.DocumentElement.Name, "objectAnimator") == 0
                    || string.Compare(doc.DocumentElement.Name, "anticipateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "overshootInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "scale") == 0
                    || string.Compare(doc.DocumentElement.Name, "set") == 0
                    || string.Compare(doc.DocumentElement.Name, "TextView") == 0
                    || string.Compare(doc.DocumentElement.Name, "ImageView") == 0
                    || string.Compare(doc.DocumentElement.Name, "RelativeLayout") == 0
                    || string.Compare(doc.DocumentElement.Name, "TextView") == 0
                    || string.Compare(doc.DocumentElement.Name, "translate") == 0
                    || string.Compare(doc.DocumentElement.Name, "View") == 0
                )*/
                )
            {
                //Console.WriteLine(" animation XML file ".PadLeft(depth, '.'));
                projectMetric.XmlAnimFileCount++;
            }
             else if (
                filePath.Contains("/res/color/")
                && filePath.EndsWith(".xml")
                )
            {
                projectMetric.XmlColorFileCount++;
            }
            else if (
                filePath.Contains("/res/font/")
                && filePath.EndsWith(".xml")
                )
            {
                projectMetric.XmlFontFileCount++;
            }
            else if (
                filePath.Contains("/res/interpolator")
                && filePath.EndsWith(".xml")
                /*&& (
                    string.Compare(doc.DocumentElement.Name, "accelerateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "accelerateDecelerateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "decelerateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "linearInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "overshootInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "anticipateInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "bounceInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "cycleInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "anticipateOvershootInterpolator") == 0
                    || string.Compare(doc.DocumentElement.Name, "pathInterpolator") == 0
                )*/
                )
            {
                projectMetric.XmlInterpolatorFileCount++;
                //Console.WriteLine(" animation XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains("/res/")
                && filePath.EndsWith("/strings.xml")
                && string.Compare(doc.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" strings XML file ".PadLeft(depth, '.'));
                if (doc.DocumentElement.HasChildNodes)
                    projectMetric.StringKeys.UnionWith(doc.DocumentElement.ChildNodes.Cast<XmlNode>().Where(c => c?.Attributes != null).Select(c => c.Attributes?.GetNamedItem("name")?.Value).Where(x => x != null).DefaultIfEmpty());
            }
            else if (
                filePath.Contains("/res/")
                && filePath.EndsWith("/styles.xml")
                && string.Compare(doc.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" styles XML file ".PadLeft(depth, '.'));
                if (doc.DocumentElement.HasChildNodes)
                    projectMetric.StyleKeys.UnionWith(doc.DocumentElement.ChildNodes.Cast<XmlNode>().Where(c => c?.Attributes != null).Select(c => c.Attributes?.GetNamedItem("name")?.Value).Where(x => x != null).DefaultIfEmpty());
            }
            else if (
                filePath.Contains("/res/drawable")
                && filePath.EndsWith(".xml")
                /*&& (
                    string.Compare(doc.DocumentElement.Name, "transition") == 0
                    || string.Compare(doc.DocumentElement.Name, "animated-rotate") == 0
                    || string.Compare(doc.DocumentElement.Name, "animated-selector") == 0
                    || string.Compare(doc.DocumentElement.Name, "animated-vector") == 0
                    || string.Compare(doc.DocumentElement.Name, "animation-list") == 0
                    || string.Compare(doc.DocumentElement.Name, "bitmap") == 0
                    || string.Compare(doc.DocumentElement.Name, "clip") == 0
                    || string.Compare(doc.DocumentElement.Name, "color") == 0
                    || string.Compare(doc.DocumentElement.Name, "fade") == 0
                    || string.Compare(doc.DocumentElement.Name, "inset") == 0
                    || string.Compare(doc.DocumentElement.Name, "layer-list") == 0
                    || string.Compare(doc.DocumentElement.Name, "level-list") == 0
                    || string.Compare(doc.DocumentElement.Name, "nine-patch") == 0
                    || string.Compare(doc.DocumentElement.Name, "objectAnimator") == 0
                    || string.Compare(doc.DocumentElement.Name, "ripple") == 0
                    || string.Compare(doc.DocumentElement.Name, "set") == 0
                    || string.Compare(doc.DocumentElement.Name, "slide") == 0
                    || string.Compare(doc.DocumentElement.Name, "transitionSet") == 0
                )*/
                )
            {
                //Console.WriteLine(" drawable XML file ".PadLeft(depth, '.'));
                projectMetric.XmlDrawableFileCount++;
            }
            else if (
                filePath.Contains("/res/transition")
                && filePath.EndsWith(".xml")
                /*&& (
                    string.Compare(doc.DocumentElement.Name, "transition") == 0
                    || string.Compare(doc.DocumentElement.Name, "explode") == 0
                    || string.Compare(doc.DocumentElement.Name, "fade") == 0
                    || string.Compare(doc.DocumentElement.Name, "objectAnimator") == 0
                    || string.Compare(doc.DocumentElement.Name, "ripple") == 0
                    || string.Compare(doc.DocumentElement.Name, "set") == 0
                    || string.Compare(doc.DocumentElement.Name, "slide") == 0
                    || string.Compare(doc.DocumentElement.Name, "transitionSet") == 0
                )*/
                )
            {
                //Console.WriteLine(" drawable XML file ".PadLeft(depth, '.'));
                projectMetric.XmlTransitionFileCount++;
            }
            else if (
                filePath.Contains("/res/values")
                && (
                    filePath.EndsWith("/attrs.xml")
                    || filePath.EndsWith("/anims.xml")
                    || filePath.EndsWith("/bools.xml")
                    || filePath.EndsWith("/colors.xml")
                    || filePath.EndsWith("/drawables.xml")
                    || filePath.EndsWith("/fractions.xml")
                    || filePath.EndsWith("/integers.xml")
                    || filePath.EndsWith("/layouts.xml")
                    || filePath.EndsWith("/ids.xml")
                    || filePath.EndsWith("/plurals.xml")
                    || filePath.EndsWith("/public.xml")
                    || filePath.EndsWith("/raws.xml")
                    || filePath.EndsWith("/xmls.xml")
                )
                && string.Compare(doc.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" built-in XML file ".PadLeft(depth, '.'));
            }
            else
            {
                var relPath = filePath.Substring(basePath.Length);
                Console.Write($"file {relPath} ".PadLeft(depth, '.'));
                Console.WriteLine($" {doc.DocumentElement.Name} ".PadLeft(depth, '.'));
            }


            /*foreach (XmlNode node in doc.DocumentElement.ChildNodes)
            {
                if (string.Compare(node.InnerText, "menu") == 0)
                {
                    Console.WriteLine(" menu ".PadLeft(depth, '.'));
                }
                else
                {
                    Console.WriteLine($" {node.Name} ".PadLeft(depth, '.'));
                }
            }*/

            return projectMetric;
        }
    }
}
