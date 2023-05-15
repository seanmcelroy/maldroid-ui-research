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

        static async Task Main(string[] args)
        {
            Console.WriteLine("Android Resource Parser and Analyzer");

            string inputPath = args[0]; // Such as "~\Downloads\Banking.tar\Banking";
            string outputPath = args[1]; // Such as ".\data\Banking2023.csv";
            const int malicious = 1;

            var metrics = new List<ProjectMetric>();
            using (var sw = new StreamWriter(outputPath))
            {
                await sw.WriteLineAsync(ProjectMetric.CsvHeader());
                foreach (var metric in RecursivelyDo(null, inputPath, "*.xml", ParseXml))
                {
                    await sw.WriteLineAsync(metric.ToCsvRow(malicious));
                    metrics.Add(metric);
                    if (metrics.Count % 10 == 0)
                        await sw.FlushAsync();
                }
            }

            Console.WriteLine($"Projects analyzed: {projectCount}");
            Console.WriteLine($"Metrics collected: {metrics.Count}");
        }

        static IEnumerable<ProjectMetric> RecursivelyDo(
            string? basePath,
            string currentPath,
            string filePattern,
            Func<string, string, int, ProjectMetric, ProjectMetric> action,
            int depth = 0,
            ProjectMetric? projectMetric = null)
        {
            var actualBase = depth == 1 ? currentPath : (basePath ?? ".");
            if (depth == 1)
            {
                Console.WriteLine($"dir {currentPath}");
                projectCount++;
                if (projectCount > maxProjects)
                    yield break;

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
                foreach (var rd in RecursivelyDo(actualBase, subdir, filePattern, action, depth + 1, projectMetric))
                    yield return rd;
            }

            foreach (var file in Directory.GetFiles(currentPath, filePattern))
            {
                if (!file.EndsWith("AndroidManifest.xml", StringComparison.OrdinalIgnoreCase)
                    && !file.Contains($"{System.IO.Path.DirectorySeparatorChar}unknown{System.IO.Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
                    projectMetric = action.Invoke(actualBase, file, depth + 1, projectMetric);
            }

            if (depth == 1)
            {
                yield return projectMetric;
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

            if (string.Compare(doc!.DocumentElement?.Name, "menu") == 0)
            {
                //Console.WriteLine(" menu ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc!.DocumentElement?.Name, "device-admin") == 0)
            {
                //Console.WriteLine(" device-admin ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc!.DocumentElement?.Name, "rotate") == 0)
            {
                //Console.WriteLine(" rotate ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc!.DocumentElement?.Name, "selector") == 0)
            {
                //Console.WriteLine(" selector ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc!.DocumentElement?.Name, "shape") == 0)
            {
                //Console.WriteLine(" shape ".PadLeft(depth, '.'));
            }
            else if (string.Compare(doc!.DocumentElement?.Name, "vector") == 0)
            {
                //Console.WriteLine(" vector ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}layout")
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

                var maxDepth = doc!.DocumentElement.MaxDepth();
                var elementCount = doc!.DocumentElement.ElementCount();
                var attributeCount = doc!.DocumentElement.AttributeCount();
                var stringRefs = doc!.DocumentElement.Attributes.Cast<XmlAttribute>().Where(a => a.Value.StartsWith("@string/")).Select(a => a.Value.Substring(8)).Distinct().ToHashSet();
                projectMetric.Layouts.Add(filePath, (maxDepth, elementCount, attributeCount, stringRefs));
            }
            else if (
                (
                    filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}xml")
                    && filePath.EndsWith(".xml")
                )
                || (
                    filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}values")
                    && filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}public.xml")
                )
            )
            {
                /*Func<XmlElement, IEnumerable<(XmlElement elem, XmlAttribute attr)>> yc = default(Func<XmlElement, IEnumerable<(XmlElement, XmlAttribute)>>);
                yc = (e) => e.Attributes.Cast<XmlAttribute>().Select(a => (e,a)).Union(e.ChildNodes.OfType<XmlElement>().SelectMany(ee => yc(ee)));
                var ycA = yc(doc!.DocumentElement).ToArray();
                var stringRefs1 = ycA
                    .Where(a => a.attr.Value.StartsWith("@string/"))
                    .Select(a => a.attr.Value.Substring(8));

                var stringRefs2 = ycA
                    .Where(a => string.Compare(a.attr.Name, "type") == 0 && string.Compare(a.attr.Value, "string") == 0)
                    .Select(a => a.elem.Attributes!["name"]!.Value);

                var stringRefs = stringRefs1.Union(stringRefs2)
                    .Distinct()
                    .ToHashSet();
                projectMetric.OtherXmls.Add(filePath, (stringRefs));*/
                //Console.WriteLine(" embedded other XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}")
                && filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}dimens.xml")
                && string.Compare(doc!.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" 'dimens' XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}")
                && filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}arrays.xml")
                && string.Compare(doc!.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" array XML file ".PadLeft(depth, '.'));
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}anim")
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
               filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}color{System.IO.Path.DirectorySeparatorChar}")
               && filePath.EndsWith(".xml")
               )
            {
                projectMetric.XmlColorFileCount++;
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}font{System.IO.Path.DirectorySeparatorChar}")
                && filePath.EndsWith(".xml")
                )
            {
                projectMetric.XmlFontFileCount++;
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}interpolator")
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
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}")
                && filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}strings.xml")
                && string.Compare(doc!.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" strings XML file ".PadLeft(depth, '.'));
                if (doc.DocumentElement.HasChildNodes)
                    projectMetric.StringKeys.UnionWith(doc!.DocumentElement.ChildNodes.Cast<XmlNode>().Where(c => c?.Attributes != null).Select(c => c.Attributes?.GetNamedItem("name")?.Value).Where(x => x != null).DefaultIfEmpty());
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}")
                && filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}styles.xml")
                && string.Compare(doc!.DocumentElement?.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" styles XML file ".PadLeft(depth, '.'));
                if (doc!.DocumentElement!.HasChildNodes)
                    projectMetric.StyleKeys.UnionWith(doc!.DocumentElement.ChildNodes.Cast<XmlNode>().Where(c => c?.Attributes != null).Select(c => c.Attributes?.GetNamedItem("name")?.Value).Where(x => x != null).DefaultIfEmpty());
            }
            else if (
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}drawable")
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
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}transition")
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
                filePath.Contains($"{System.IO.Path.DirectorySeparatorChar}res{System.IO.Path.DirectorySeparatorChar}values")
                && (
                    filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}attrs.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}anims.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}bools.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}colors.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}drawables.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}fractions.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}integers.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}layouts.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}ids.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}plurals.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}public.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}raws.xml")
                    || filePath.EndsWith($"{System.IO.Path.DirectorySeparatorChar}xmls.xml")
                )
                && string.Compare(doc!.DocumentElement.Name, "resources") == 0
                )
            {
                //Console.WriteLine(" built-in XML file ".PadLeft(depth, '.'));
            }
            else
            {
                //var relPath = filePath.Substring(basePath.Length);
                //Console.Write($"file {relPath} ".PadLeft(depth, '.'));
                //Console.WriteLine($" {doc!.DocumentElement.Name} ".PadLeft(depth, '.'));
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
