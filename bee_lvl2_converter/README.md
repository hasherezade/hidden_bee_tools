# bee_lvl2_converter

Converts a custom executable formats used by:
+    Hidden Bee miner
+    Rhadamanthys stealer
  
into a PE.

#  Supported formats


## Rhadamanthys
+ RS
+ HS
+ XS (v1 and v2)

## Hidden Bee
+ NE
+ NS


### NE Format:

Changes in the PE header:<br/>

![diagram](../pics/scrambled_pe1.png)

### NS Format:

Changes in the PE header:<br/>

![diagram](../pics/ns_format1.png)
<br/>

Shrinked Import Table:

![diagram](../pics/ns_format_imports.png)
