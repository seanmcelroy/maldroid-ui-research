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