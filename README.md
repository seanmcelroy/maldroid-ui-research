# maldroid-ui-research

This project contains a C# project that can recursively analyze a directory of
Android APK files unpacked by ```Apktool```.  The program's output is a CSV
file containing features that can be used to classify the contents as malicious
or not, using an analysis of user interface features, such as the 
characteristics of XML layout files and other static elements within the
resources of the APK.

This C# program is an artifact that accompanies the research paper:

&quot;Identifying Android Banking Malware through Measurement of User Interface
Complexity" by Sean A. McElroy.&quot;