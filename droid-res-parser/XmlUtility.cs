using System;
using System.Collections.Generic;
using System.Xml;

namespace droid_res_parser
{
    static class XmlUtility
    {
        public static int MaxDepth(this XmlNode node, int depth = 0)
        {
            if (!node.HasChildNodes)
                return 0;

            var max = depth + 1;
            foreach (XmlNode child in node.ChildNodes)
            {
                max = Math.Max(max, child.MaxDepth(depth + 1));
            }
            return max;
        }

        public static int ElementCount(this XmlNode node)
        {
            if (!node.HasChildNodes)
                return 1;

            var ct = 1;
            foreach (XmlNode child in node.ChildNodes)
            {
                ct += child.ElementCount();
            }
            return ct;
        }

        public static int AttributeCount(this XmlNode node)
        {
            if (!node.HasChildNodes)
                return 0;

            var ct = node.Attributes?.Count ?? 0;

            foreach (XmlNode child in node.ChildNodes)
            {
                ct += child.AttributeCount();
            }
            return ct;
        }
    }
}