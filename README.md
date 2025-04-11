# IIS_GEN - IIS Tilde Enumeration Dictionary Generator

A specialized bash tool for creating wordlists specifically designed to exploit the IIS tilde enumeration vulnerability. It generates optimized dictionaries for guessing hidden files and directories by leveraging the short-name (8.3) disclosure technique in vulnerable IIS servers.

## Installation

```bash
git clone https://github.com/nemmusu/iis_gen.git
cd iis_gen
chmod +x iis_gen.sh
```

## Requirements

- Bash 4.0+
- Standard Unix utilities: grep, sed, awk, sort, find
- Supports Linux/Unix environments and macOS

## Overview

IIS_GEN processes existing dictionaries to create wordlists specifically optimized for exploiting the IIS tilde enumeration vulnerability. The tool filters and manipulates input lists to generate dictionaries of potential filenames and paths that can be used in the guessing process when leveraging this vulnerability.

## Technical Background

Microsoft IIS servers maintain 8.3 format filenames (short names) for compatibility with legacy systems. A security vulnerability allows attackers to enumerate these short names through crafted requests using the tilde (~) character, effectively disclosing hidden files and directories. This tool helps generate targeted dictionaries for guessing these file and directory names by processing existing wordlists into formats that maximize the effectiveness of the exploitation technique.

The tool enhances the guessing attack by:
- Extracting entries that match patterns likely to be found in target IIS environments
- Applying filters to format words for maximum success in the guessing process
- Creating optimized dictionaries that increase the chance of successfully exploiting the vulnerability

## Functions

- **Dictionary Processing:** 
  - Unifies case variants (keeps one variant per word)
  - Maintains original case with optional lowercase conversion
  - Skips binary files automatically
  - Supports parallel processing

- **Filtering Capabilities:**
  - Keyword prefix or regex filtering
  - Length constraints (min/max) for both main wordlists and secondary lists
  - Character type filtering (numbers, special chars)
  - Extension inclusion/exclusion

- **Word Manipulation:**
  - List intersection for common entries
  - Cross-combination with separators
  - Pair-combine for one-to-one word combinations (with cycling option)
  - Text transform operations (append, prepend, replace)

## Complete Usage Guide

### Basic Operations

Extract words starting with a specific prefix:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config
```

Use regex pattern instead of prefix:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k "^conf[a-z]+" -r
```

Apply length filters:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config --min-length 5 --max-length 12
```

Filter out entries with numbers or remove special characters from words:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user --remove-numbers # Removes words containing numbers
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user --remove-special # Strip special chars, keep alphanumeric, _ and -
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user --remove-chars ".,/" # Remove only periods, commas and slashes
```

### File Selection

Process only specific file extensions:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config -e txt,lst,dict
```

Ignore specific file extensions:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user -i bak,tmp,log
```

Binary files are skipped automatically. To process all files:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config --no-binary-check
```

### Text Transformation

Convert output to lowercase:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user --lowercase
```

Append or prepend strings:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config --append ".txt"
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config --prepend "backup_"
```

Replace patterns in words:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k configuration --replace "ion:1on"
```

Another replace example:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k web --replace ".txt:.aspx" # Pattern replacement
```

### List Manipulation

Combine words from additional lists:

```bash
# Default mode is now pair-combine (first+first, second+second, etc.)
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user --combine /path/to/list1.txt

# Create all possible combinations between lists
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config --cross-combine --combine /path/to/numbers.txt --combine-sep "-"

# Combine words one-to-one (first with first, second with second)
./iis_gen.sh -d /path/to/wordlists -o output.txt -k admin --pair-combine --combine /path/to/config_list.txt

# Combine words one-to-one but reuse shorter list if needed
./iis_gen.sh -d /path/to/wordlists -o output.txt -k admin --pair-combine-cycle --combine /path/to/short_list.txt
```

Separator options:
- Default: `--combine-sep "_"`
- Others: `--combine-sep "."`, `--combine-sep "-"`, `--combine-sep ""`

### Performance Options

Control parallel processing:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user -j 8
```

Backup existing output file:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k config -b
```

Verbose output with detailed processing information:

```bash
./iis_gen.sh -d /path/to/wordlists -o output.txt -k user -v
```

## Example Output

Below is an example of running the tool with the following parameters:
- Directory: `test_data/iis_folders` (containing common IIS folder names)
- Keyword: `default` (targeting realistic IIS folder structures)
- Verbose output

```
+--------------------------------------------------------------------------------+
|                                                                                |
|                   IIS Tilde Enumeration Dictionary Generator                   |
|          Wordlists for IIS short-name (8.3) disclosure vulnerability           |
|                                                                                |
+--------------------------------------------------------------------------------+

[+] Scanning 'test_data/iis_folders' for dictionary files...
[+] Found 1 files                      
[+] Found 1 files to process (55 bytes)
[INFO] Filtering words starting with keyword: default
[INFO] Using case-insensitive matching

+-------------------------------------+
|     Processing Dictionary Files     |
+-------------------------------------+

[INFO] Processed: test_data/iis_folders/iis_folders.txt (1/1)
[##################################################] 100% (1/1)


+---------------------------------+
|     Post-Processing Results     |
+---------------------------------+

[INFO] Applying case unification (preserving only one variant per word)
[INFO] Step 1/3: Creating case-insensitive map...
[INFO] Step 2/3: Sorting variants...
[INFO] Step 3/3: Unifying variants... 100% (5/5)
[INFO] Applying post-processing filters...


+-------------------------+
|     Results Summary     |
+-------------------------+

+-------------------------------------------+
|           Dictionary Statistics           |
|                                           |
|  Output file: output/realistic_folders.txt|
|                                           |
|  Total entries: 5 unique words            |
|                                           |
|  File size: 55 bytes                      |
|                                           |
|  Average word length: 10.0 characters     |
|                                           |
|  Case format: Original case preserved     |
|                                           |
+-------------------------------------------+

[INFO] Preview of results (first 5 entries):
    default
    defaultadmin
    defaultapp 
    defaultsite
    defaultweb

+----------------------------------------------------------+
|                     Process Complete                     |
|                                                          |
|  Dictionary generation completed successfully!           |
|                                                          |
|  Words have been saved to: output/realistic_folders.txt  |
|                                                          |
+----------------------------------------------------------+
```

## Parameters Reference

### Required Parameters
- `-d, --directory DIR` - Directory containing wordlist files
- `-o, --output FILE` - Output file path
- `-k, --keyword WORD` - Keyword to filter (default: words starting with this)

### Filter Parameters
- `-r, --regex` - Use regex for keyword matching
- `--lowercase` - Convert all output to lowercase
- `--min-length NUM` - Minimum word length for main wordlist
- `--max-length NUM` - Maximum word length for main wordlist
- `--combine-min-length NUM` - Minimum length for words in secondary lists before combining
- `--combine-max-length NUM` - Maximum length for words in secondary lists before combining
- `--remove-numbers` - Remove words containing numbers
- `--remove-special` - Remove special characters from words (keeps alphanumeric, underscore and hyphen)
- `--remove-chars CHARS` - Remove specific characters from words (e.g. ".,/" removes periods, commas, slashes)
- `-e, --extensions LIST` - Process only specific extensions (comma-separated)
- `-i, --ignore LIST` - Ignore specific extensions (comma-separated)

### Transformation Parameters
- `--combine FILES` - Combine words from specified files (defaults to pair-combine)
- `--cross-combine` - Generate all combinations between lists
- `--pair-combine` - Combine words one-to-one (first with first, second with second)
- `--pair-combine-cycle` - Like pair-combine but reuse shorter list if needed
- `--combine-sep SEP` - Separator for combinations (default: "_") 
- `--append STR` - Append string to each word
- `--prepend STR` - Prepend string to each word
- `--replace PAT:REP` - Replace pattern with replacement

### Operation Parameters
- `-j, --jobs NUM` - Number of parallel jobs (default: 4)
- `-b, --backup` - Create backup if output file exists
- `-v, --verbose` - Increase output verbosity
- `-h, --help` - Display help information


