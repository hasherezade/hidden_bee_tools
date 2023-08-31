# bee_lvl2_converter

Converts a custom executable formats used by:
+    Hidden Bee miner
+    Rhadamanthys stealer
  
into a PE.

# Usage

```
Converter for Hidden Bee & Rhadamanthys custom executable formats
Args: <input module> <is_mapped?> <module base>
```

+ `input module` -> custom module of Hidden Bee or Rhadamanthys, in one of the supported formats (see below)
+ `is_mapped` -> `0` if the module in a raw format, `1` if in virtual.
+ `module base` -> if the module was relocated to the load base, you need to input the base here


#  Supported formats

## Rhadamanthys
+ RS
+ HS
+ XS (v1 and v2)

More details: https://research.checkpoint.com/2023/from-hidden-bee-to-rhadamanthys-the-evolution-of-custom-executable-formats/

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
