#!/bin/bash
#
# IIS_GEN - IIS Tilde Enumeration Dictionary Generator
# A specialized tool for creating wordlists targeting IIS short-name (8.3) disclosure vulnerability
# Author: Created for IIS tilde enumeration attacks and short-name detection
#

# Text colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
NC='\033[0m' # No Color

# Default options flags

# Box drawing characters - using ASCII for better compatibility
BOX_TL="+"
BOX_TR="+"
BOX_BL="+"
BOX_BR="+"
BOX_H="-"
BOX_V="|"
ARROW=">"

# Default values
DIRECTORY=""
OUTPUT=""
KEYWORD=""
CASE_SENSITIVE=0
BACKUP=0
VERBOSE=0
MAX_THREADS=4
IGNORE_EXTENSIONS=""
ONLY_EXTENSIONS=""
REMOVE_NUMBERS=0
REMOVE_SPECIAL=0
REMOVE_CHARS=""
MIN_LENGTH=0
MAX_LENGTH=0
COMBINE_MIN_LENGTH=0
COMBINE_MAX_LENGTH=0
APPEND_STRING=""
PREPEND_STRING=""
REPLACE_PATTERN=""
REPLACE_WITH=""
REGEX_MODE=0
FORCE_LOWERCASE=0
COMBINE_LISTS=0
COMBINE_MODE="AND"
COMBINE_FILES=""
COMBINE_WORDS=0
CROSS_COMBINE=0
PAIR_COMBINE=0
CYCLE_COMBINE=0
COMBINE_SEPARATOR="_"
SKIP_BINARY=1
FORCE_LOWERCASE=0
DEFAULT_PAIR_COMBINE=1  # Usa pair-combine come default quando si specifica solo --combine
GENERATE_HTML_VARIANTS=1  # Genera varianti .htm e .html automaticamente
TEMP_DIR=$(mktemp -d)

# Function to apply length and character filters to a wordlist
apply_filters() {
    local input_file="$1"
    local output_file="$2"
    local min_length="$3"
    local max_length="$4"
    local remove_numbers="$5"
    local remove_special="$6"
    local remove_chars="$7"
    local filter_name="$8"  # Nome identificativo per i messaggi
    
    # Create a temporary filter pipeline
    local filter_cmds="cat \"$input_file\" | "
    
    # Apply minimum length filtering if specified
    if [[ "$min_length" -gt 0 ]]; then
        echo -e "[${BLUE}INFO${NC}] ${filter_name}: Filtering words with minimum length of $min_length"
        filter_cmds+="awk 'length >= $min_length' | "
    fi
    
    # Apply maximum length filtering if specified
    if [[ "$max_length" -gt 0 ]]; then
        echo -e "[${BLUE}INFO${NC}] ${filter_name}: Filtering words with maximum length of $max_length"
        filter_cmds+="awk 'length <= $max_length' | "
    fi
    
    # Remove words with numbers if requested
    if [[ "$remove_numbers" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] ${filter_name}: Removing words containing numbers"
        filter_cmds+="grep -v '[0-9]' | "
    fi
    
    # Remove special characters if requested
    if [[ "$remove_special" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] ${filter_name}: Removing special characters from words (keeping only alphanumeric, underscore and hyphen)"
        filter_cmds+="sed 's/[^a-zA-Z0-9_-]//g' | grep -v '^$' | "
    fi
    
    # Remove specific characters if requested
    if [[ -n "$remove_chars" ]]; then
        echo -e "[${BLUE}INFO${NC}] ${filter_name}: Removing specified characters: $remove_chars"
        # Escape special characters for sed
        local escaped_chars=$(echo "$remove_chars" | sed 's/[][\/]/\\&/g')
        filter_cmds+="sed 's/[$escaped_chars]//g' | grep -v '^$' | "
    fi
    
    # Finish with sort -u
    filter_cmds+="sort -u > \"$output_file\""
    
    # Execute the filter pipeline
    eval "$filter_cmds"
    
    # Return word count for reporting
    wc -l < "$output_file"
}

# Function to display usage
show_usage() {
    echo -e "${BOLD}IIS_GEN - IIS Tilde Enumeration Dictionary Generator${NC}"
    echo "A specialized tool for creating wordlists targeting IIS short-name (8.3) disclosure vulnerability"
    echo ""
    echo -e "${BOLD}Basic Usage:${NC} $0 -d directory -o output.txt -k keyword"
    echo ""
    echo -e "${BOLD}Required Arguments:${NC}"
    echo "  -d, --directory DIR    Directory containing dictionary files"
    echo "  -o, --output FILE      Output file for the new dictionary"
    echo "  -k, --keyword WORD     Keyword to filter (words starting with this)"
    echo ""
    echo -e "${BOLD}Filter Options:${NC}"
    echo "  -r, --regex            Use regex pattern for keyword matching"
    echo "  --lowercase            Force output to lowercase (default: preserve original case)"
    echo "  -e, --extensions LIST  Only process files with these extensions (comma-separated)"
    echo "  -i, --ignore LIST      Ignore files with these extensions (comma-separated)"
    echo "  --min-length NUM       Only include words with at least NUM characters"
    echo "  --max-length NUM       Only include words with at most NUM characters"
    echo "  --combine-min-length NUM       Minimum length for words in secondary lists before combining"
    echo "  --combine-max-length NUM       Maximum length for words in secondary lists before combining"
    echo "  --remove-numbers       Remove words containing numbers"
    echo "  --remove-special       Remove special characters from words (keeps alphanumeric, underscore and hyphen)"
    echo "  --remove-chars CHARS   Remove specified characters from words (e.g. \".,/\" removes periods, commas, slashes)"
    echo "  --no-binary-check      Don't skip binary files (default: binary files are skipped)"
    echo ""
    echo -e "${BOLD}Combining Lists:${NC}"
    echo "  --combine FILE1,FILE2  Combine words from these files (defaults to pair-combine if no mode specified)"
    echo "  --cross-combine        Generate all combinations of words between lists"
    echo "  --pair-combine         Combine words one-to-one (first with first, second with second, etc.)"
    echo "  --pair-combine-cycle   Like --pair-combine but reuse shorter list cyclically if needed"
    echo "  --combine-sep SEP      Separator for combined words (default: '_')"
    echo ""
    echo -e "${BOLD}Processing Options:${NC}"
    echo "  --append STR           Append string to each word (use spaces to separate multiple extensions, e.g. '.htm .html')"
    echo "  --prepend STR          Prepend string to each word"
    echo "  --replace PAT:REP      Replace pattern with replacement in each word"
    echo "  -j, --jobs NUM         Number of parallel jobs (default: 4)"
    echo ""
    echo -e "${BOLD}Other Options:${NC}"
    echo "  -b, --backup           Create a backup of output file if it exists"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -h, --help             Display this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 -d /usr/share/wordlists -o web_paths.txt -k config"
    echo "  $0 -d /wordlists -o iis_files.txt -k web -r --min-length 5"
    echo "  $0 -d /wordlists -o output.txt -k '^aspnet' -r --append .txt" 
    echo "  $0 -d /wordlists -o multi_ext.txt -k 'web' --append '.htm .html'"
    echo "  $0 -d /wordlists -o combined.txt -k default --combine /path/to/custom_list.txt"
    echo "  $0 -d /wordlists -o cross.txt -k webconfig --cross-combine --combine /path/to/extensions.txt --combine-sep '.'"
    echo "  $0 -d /wordlists -o pair.txt -k admin --pair-combine --combine /path/to/config_list.txt --combine-sep '-'"
    echo "  $0 -d /wordlists -o cycling.txt -k admin --pair-combine-cycle --combine /path/to/short_list.txt"
    echo "  $0 -d /wordlists -o extensions.txt -k 'web' --replace '.txt:.html'"
    echo "  $0 -d /wordlists -o clean.txt -k config --remove-special"
    echo "  $0 -d /wordlists -o filtered.txt -k web --remove-chars \".,_-\""
}

# Function to clean temporary files
cleanup() {
    rm -rf "${TEMP_DIR}"
    echo -e "\n[${RED}!${NC}] Process interrupted. Cleaning up temporary files..."
    exit 1
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Print a fancy header for the tool
print_header() {
    # Configurazione dell'header principale
    local width=80  # Larghezza predefinita
    local title="IIS Tilde Enumeration Dictionary Generator"
    local subtitle="Wordlists for IIS short-name (8.3) disclosure vulnerability"
    
    # Assicurati che la larghezza sia sufficiente per i titoli
    local min_width=$(( ${#title} > ${#subtitle} ? ${#title} : ${#subtitle} ))
    min_width=$((min_width + 10))  # Padding aggiuntivo
    
    # Usa la larghezza maggiore
    if (( min_width > width )); then
        width=$min_width
    fi
    
    # Bordo superiore
    local top_border="${CYAN}+"
    for ((i=0; i<width; i++)); do
        top_border+="-"
    done
    top_border+="+"
    
    # Linea vuota
    local empty_line="${CYAN}|"
    for ((i=0; i<width; i++)); do
        empty_line+=" "
    done
    empty_line+="|"
    
    # Titolo centrato
    local title_len=${#title}
    local padding_left=$(( (width - title_len) / 2 ))
    local padding_right=$(( width - title_len - padding_left ))
    
    local title_line="${CYAN}|"
    for ((i=0; i<padding_left; i++)); do
        title_line+=" "
    done
    title_line+="${BOLD}${title}${NC}${CYAN}"
    for ((i=0; i<padding_right; i++)); do
        title_line+=" "
    done
    title_line+="|"
    
    # Sottotitolo centrato
    local subtitle_len=${#subtitle}
    local sub_padding_left=$(( (width - subtitle_len) / 2 ))
    local sub_padding_right=$(( width - subtitle_len - sub_padding_left ))
    
    local subtitle_line="${CYAN}|"
    for ((i=0; i<sub_padding_left; i++)); do
        subtitle_line+=" "
    done
    subtitle_line+="${DIM}${subtitle}${NC}${CYAN}"
    for ((i=0; i<sub_padding_right; i++)); do
        subtitle_line+=" "
    done
    subtitle_line+="|"
    
    # Bordo inferiore
    local bottom_border="${CYAN}+"
    for ((i=0; i<width; i++)); do
        bottom_border+="-"
    done
    bottom_border+="+"
    
    # Visualizza il box completo
    echo
    echo -e "$top_border${NC}"
    echo -e "$empty_line${NC}"
    echo -e "$title_line${NC}"
    echo -e "$subtitle_line${NC}"
    echo -e "$empty_line${NC}"
    echo -e "$bottom_border${NC}"
    echo
}

# Print a section header with COMPLETELY STATIC box alignment
print_section_header() {
    local section_title="$1"
    local min_width=20  # Larghezza minima per il box
    
    echo
    
    # Calcola la larghezza esatta necessaria per il titolo
    local title_len=${#section_title}
    local box_width=$((title_len + 10))  # Aggiungi un po' di padding
    
    # Non scendere mai sotto la larghezza minima
    if (( box_width < min_width )); then
        box_width=$min_width
    fi
    
    # Bordo superiore della dimensione esatta
    local top_border="${PURPLE}+"
    for ((i=0; i<box_width; i++)); do
        top_border+="-"
    done
    top_border+="+"
    echo -e "$top_border${NC}"
    
    # Titolo centrato con precisione
    local padding_left=$(( (box_width - title_len) / 2 ))
    local padding_right=$(( box_width - title_len - padding_left ))
    
    local title_line="${PURPLE}|"
    for ((i=0; i<padding_left; i++)); do
        title_line+=" "
    done
    title_line+="${BOLD}$section_title${NC}${PURPLE}"
    for ((i=0; i<padding_right; i++)); do
        title_line+=" "
    done
    title_line+="|"
    echo -e "$title_line${NC}"
    
    # Bordo inferiore perfettamente allineato
    local bottom_border="${PURPLE}+"
    for ((i=0; i<box_width; i++)); do
        bottom_border+="-"
    done
    bottom_border+="+"
    echo -e "$bottom_border${NC}"
    
    echo
}

# Print a statistics box with DYNAMIC sizing for content
print_stats_box() {
    local title="$1"
    local stats=("${@:2}")
    local min_width=20  # Larghezza minima di base ridotta (più compatta)
    local content_lines=()
    local i=0
    
    # Prepara il contenuto in base al tipo di box
    if [[ "$title" == "Dictionary Statistics" ]]; then
        # Raccogli tutte le righe di contenuto per il box statistiche
        content_lines[$i]="Output file: $OUTPUT"; ((i++))
        content_lines[$i]="Total entries: ${BOLD}$RESULT_COUNT${NC} unique words"; ((i++))
        content_lines[$i]="File size: $(format_size $OUTPUT_SIZE)"; ((i++))
        content_lines[$i]="Average word length: ${BOLD}$AVG_WORD_LEN${NC} characters"; ((i++))
        
        # Case format info
        if [[ "$FORCE_LOWERCASE" -eq 1 ]]; then
            content_lines[$i]="Case format: Forced lowercase"; ((i++))
        else
            content_lines[$i]="Case format: Original case preserved"; ((i++))
        fi
        
        # Combination info if applicable
        if [[ "$COMBINE_LISTS" -eq 1 ]]; then
            if [[ "$CROSS_COMBINE" -eq 1 ]]; then
                content_lines[$i]="Combination: Cross-combined with separator '$COMBINE_SEPARATOR'"; ((i++))
            elif [[ "$PAIR_COMBINE" -eq 1 ]]; then
                if [[ "$CYCLE_COMBINE" -eq 1 ]]; then
                    content_lines[$i]="Combination: One-to-one combined with separator '$COMBINE_SEPARATOR' (cycling)"; ((i++))
                else
                    content_lines[$i]="Combination: One-to-one combined with separator '$COMBINE_SEPARATOR'"; ((i++))
                fi
            else
                content_lines[$i]="Combination: Intersection mode with custom files"; ((i++))
            fi
        fi
    
    elif [[ "$title" == "Process Complete" ]]; then
        content_lines[$i]="Dictionary generation completed successfully!"; ((i++))
        content_lines[$i]="Words have been saved to: $OUTPUT"; ((i++))
    
    else
        # Per qualsiasi altro box 
        for stat in "${stats[@]}"; do
            content_lines[$i]="$stat"; ((i++))
        done
    fi
    
    # Calcola la larghezza esatta necessaria per il contenuto più lungo
    local content_width=0
    local title_len=${#title}
    
    # Considera innanzitutto la lunghezza del titolo
    if (( title_len > content_width )); then
        content_width=$title_len
    fi
    
    # Poi controlla ogni riga di contenuto
    for line in "${content_lines[@]}"; do
        # Rimuovi i codici ANSI per un calcolo accurato della lunghezza
        local plain_line=$(echo -e "$line" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
        local line_len=${#plain_line}
        if (( line_len > content_width )); then
            content_width=$line_len
        fi
    done
    
    # Aggiungi padding minimo (2 spazi a sinistra e 2 a destra)
    local box_width=$((content_width + 4))
    
    # Non scendere mai sotto la larghezza minima
    if (( box_width < min_width )); then
        box_width=$min_width
    fi
    
    # Disegna bordo superiore della dimensione esatta
    local border_line="${BLUE}+"
    for ((i=0; i<box_width; i++)); do
        border_line+="-"
    done
    border_line+="+"
    echo -e "$border_line${NC}"
    
    # Titolo centrato
    local header_len=${#title}
    local padding_left=$(( (box_width - header_len) / 2 ))
    local padding_right=$(( box_width - header_len - padding_left ))
    
    local header_line="${BLUE}|"
    for ((i=0; i<padding_left; i++)); do
        header_line+=" "
    done
    header_line+="${BOLD}$title${NC}${BLUE}"
    for ((i=0; i<padding_right; i++)); do
        header_line+=" "
    done
    header_line+="|"
    echo -e "$header_line${NC}"
    
    # Linea vuota dopo il titolo
    local empty_line="${BLUE}|"
    for ((i=0; i<box_width; i++)); do
        empty_line+=" "
    done
    empty_line+="|"
    echo -e "$empty_line${NC}"
    
    # Contenuto con spaziatura uniforme
    for line in "${content_lines[@]}"; do
        # Rimuovi i codici di colore ANSI per un calcolo accurato della lunghezza
        local plain_line=$(echo -e "$line" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
        local line_len=${#plain_line}
        
        # Calcola spazi rimanenti
        local remaining_space=$((box_width - line_len))
        local left_space=2  # Spazio fisso a sinistra
        local right_space=$((remaining_space - left_space))
        
        # Componi la riga con spazio corretto
        local content_line="${BLUE}|${NC}"
        
        # Aggiungi spazio a sinistra
        for ((i=0; i<left_space; i++)); do
            content_line+=" "
        done
        
        # Aggiungi il contenuto
        content_line+="$line"
        
        # Aggiungi spazio a destra
        for ((i=0; i<right_space; i++)); do
            content_line+=" "
        done
        
        # Chiudi la riga
        content_line+="${BLUE}|"
        echo -e "$content_line${NC}"
        
        # Linea vuota dopo ogni elemento
        echo -e "$empty_line${NC}"
    done
    
    # Bordo inferiore perfettamente allineato
    echo -e "$border_line${NC}"
}

# Function to display progress
show_progress() {
    local processed=$1
    local total=$2
    local width=50
    
    # Update the global progress counter
    PROGRESS_INFO["current"]=$processed
    processed=${PROGRESS_INFO["current"]}
    total=${PROGRESS_INFO["total"]}
    
    # Prevent division by zero
    if [[ $total -eq 0 ]]; then
        total=1
    fi
    
    # Ensure processed is at least 1 but not greater than total
    if [[ $processed -eq 0 ]]; then
        processed=1
    fi
    
    # Ensure processed isn't greater than total
    if [[ $processed -gt $total ]]; then
        processed=$total
    fi
    
    # Calculate percentage with awk for better accuracy
    local percentage=$(awk "BEGIN {printf \"%.0f\", ($processed/$total)*100}")
    
    # Calculate how many characters to fill
    local fill=$(awk "BEGIN {printf \"%.0f\", ($processed/$total)*$width}")
    if [[ -z "$fill" || "$fill" -lt 1 ]]; then
        fill=1  # Ensure at least some progress is shown
    fi
    
    # Choose color based on progress
    local color="${BLUE}"
    if (( percentage >= 75 )); then
        color="${GREEN}"
    elif (( percentage >= 50 )); then
        color="${CYAN}"
    elif (( percentage >= 25 )); then
        color="${YELLOW}"
    fi
    
    # Create the progress bar with enhanced visuals - using cross-platform character
    local bar=""
    for ((i=0; i<$fill; i++)); do
        bar+="#"
    done
    
    printf "\r${BOLD}[${color}%-${width}s${NC}${BOLD}]${NC} ${BOLD}%3d%%${NC} (%d/%d)" "$bar" "$percentage" "$processed" "$total"
}

# Function to format file size without using bc
format_size() {
    local size=$1
    if (( size > 1073741824 )); then
        local gb=$(awk "BEGIN {printf \"%.2f\", $size/1073741824}")
        printf "%s GB" "$gb"
    elif (( size > 1048576 )); then
        local mb=$(awk "BEGIN {printf \"%.2f\", $size/1048576}")
        printf "%s MB" "$mb"
    elif (( size > 1024 )); then
        local kb=$(awk "BEGIN {printf \"%.2f\", $size/1024}")
        printf "%s KB" "$kb"
    else
        printf "%d bytes" $size
    fi
}

# Trap Ctrl+C
trap cleanup SIGINT

# Function to check if a file is binary
is_binary_file() {
    local file="$1"
    local binary=0
    
    # Simple check for very common binary file extensions
    if [[ "$file" == *.exe || "$file" == *.zip || "$file" == *.gz || 
          "$file" == *.jpg || "$file" == *.png || "$file" == *.pdf ]]; then
        binary=1
        return $binary
    fi
    
    # Check for null bytes which are strong indicators of binary content
    if [[ "$NEED_SUDO" -eq 1 ]]; then
        if sudo grep -q $'\x00' "$file" 2>/dev/null; then
            binary=1
            return $binary
        fi
    else
        if grep -q $'\x00' "$file" 2>/dev/null; then
            binary=1
            return $binary
        fi
    fi
    
    # If those checks pass, assume it's a text file
    return $binary
}

# Cross combine words from two lists with a separator
cross_combine_words() {
    local list1="$1"
    local list2="$2" 
    local separator="$3"
    local output="$4"
    local temp_output="$TEMP_DIR/cross_temp.txt"
    
    # Check if we have append/prepend options active
    local append_str="${APPEND_STRING}"
    local prepend_str="${PREPEND_STRING}"
    local using_special_combine=0
    
    if [[ -n "$append_str" || -n "$prepend_str" ]]; then
        using_special_combine=1
        echo -e "[${BLUE}INFO${NC}] Cross combining with prepend/append applied only once per combined word"
    fi
    
    echo -e "[${BLUE}INFO${NC}] Cross combining all words using separator '$separator'"
    > "$temp_output"
    
    # For each word in the first list
    while IFS= read -r word1; do
        # Combine with each word in the second list
        while IFS= read -r word2; do
            if [[ "$using_special_combine" -eq 1 ]]; then
                # Apply prepend only to the first word and append only to the last word
                echo "${prepend_str}${word1}${separator}${word2}${append_str}" >> "$temp_output"
            else
                # Standard behavior without prepend/append
                echo "${word1}${separator}${word2}" >> "$temp_output"
            fi
        done < "$list2"
    done < "$list1"
    
    # Move to output
    if [[ -s "$temp_output" ]]; then
        sort -u "$temp_output" > "$output"
    else
        # Create empty file if no combinations generated
        touch "$output"
    fi
}

# Pair combine words from two lists with a separator (one-to-one)
pair_combine_words() {
    local list1="$1"
    local list2="$2" 
    local separator="$3"
    local output="$4"
    local temp_output="$TEMP_DIR/pair_temp.txt"
    
    # Check if we have append/prepend options active
    local append_str="${APPEND_STRING}"
    local prepend_str="${PREPEND_STRING}"
    local using_special_combine=0
    
    if [[ -n "$append_str" || -n "$prepend_str" ]]; then
        using_special_combine=1
        echo -e "[${BLUE}INFO${NC}] Pair combining with prepend/append applied only once per combined word"
    fi
    
    if [[ "$CYCLE_COMBINE" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] Pair combining words using separator '$separator' (with cycling)"
    else
        echo -e "[${BLUE}INFO${NC}] Pair combining words using separator '$separator'"
    fi
    
    > "$temp_output"
    
    # Create arrays to hold the words from both lists
    mapfile -t list1_words < "$list1"
    mapfile -t list2_words < "$list2"
    
    # Get the count of words in each list
    local count1=${#list1_words[@]}
    local count2=${#list2_words[@]}
    
    # Determine how many combinations to generate
    local combinations=$count1
    if [[ "$CYCLE_COMBINE" -eq 0 && $count2 -lt $count1 ]]; then
        # If not cycling and list2 is shorter, limit to length of list2
        combinations=$count2
    fi
    
    echo -e "[${BLUE}INFO${NC}] List 1: $count1 words, List 2: $count2 words"
    
    # Generate pairs
    for ((i=0; i<combinations; i++)); do
        local word1="${list1_words[$i]}"
        local idx2=$i
        
        # If cycling and we've reached the end of list2, wrap around
        if [[ $idx2 -ge $count2 ]]; then
            if [[ "$CYCLE_COMBINE" -eq 1 ]]; then
                idx2=$((idx2 % count2)) # Wrap around using modulo
            else
                # We've exhausted list2 and not cycling
                break
            fi
        fi
        
        local word2="${list2_words[$idx2]}"
        
        # Format output based on options
        if [[ "$using_special_combine" -eq 1 ]]; then
            # Apply prepend/append only once to the combined result
            echo "${prepend_str}${word1}${separator}${word2}${append_str}" >> "$temp_output"
        else
            # Standard behavior without prepend/append
            echo "${word1}${separator}${word2}" >> "$temp_output"
        fi
    done
    
    # Move to output
    if [[ -s "$temp_output" ]]; then
        sort -u "$temp_output" > "$output"
    else
        # Create empty file if no combinations generated
        touch "$output"
    fi
    
    local total_pairs=$(wc -l < "$output")
    echo -e "[${BLUE}INFO${NC}] Generated $total_pairs unique word pairs"
}

# Combine list function 
combine_lists() {
    local main_list="$1"
    local combined_list="$2"
    local mode="$3"  # Keeping parameter for backward compatibility
    local output="$4"
    
    if [[ "$CROSS_COMBINE" -eq 1 ]]; then
        # Cross combine with separator
        cross_combine_words "$main_list" "$combined_list" "$COMBINE_SEPARATOR" "$output"
    elif [[ "$PAIR_COMBINE" -eq 1 ]]; then
        # Pair combine with separator (one-to-one)
        pair_combine_words "$main_list" "$combined_list" "$COMBINE_SEPARATOR" "$output"
    elif [[ "$DEFAULT_PAIR_COMBINE" -eq 1 ]]; then
        # Use pair-combine as default when no other mode specified
        echo -e "[${BLUE}INFO${NC}] Using pair-combine as default mode (one-to-one matching)"
        pair_combine_words "$main_list" "$combined_list" "$COMBINE_SEPARATOR" "$output"
    else
        # Always use intersection mode (AND)
        echo -e "[${BLUE}INFO${NC}] Combining lists using intersection mode"
        
        # If we have clean version of the words (before prepend/append), use those for matching
        local main_clean="$main_list"
        if [[ -n "$PREPEND_STRING" || -n "$APPEND_STRING" ]] && [[ -f "$TEMP_DIR/clean_unified.txt" ]]; then
            # Use the clean version for matching
            echo -e "[${BLUE}INFO${NC}] Using clean words (without prepend/append) for intersection matching"
            main_clean="$TEMP_DIR/clean_unified.txt"
        fi
        
        # Create temporary files for processing
        sort "$main_clean" | uniq > "$TEMP_DIR/main_sorted.txt"
        sort "$combined_list" | uniq > "$TEMP_DIR/combined_sorted.txt"
        
        echo -e "[${BLUE}INFO${NC}] Finding words present in both lists (intersection mode)"
        
        # Check if we need to handle append/prepend by showing original contents
        if [[ -v VERBOSE && "$VERBOSE" -eq 1 ]]; then
            echo -e "[${BLUE}INFO${NC}] Debug: displaying file contents for main list"
            head -n 5 "$TEMP_DIR/main_sorted.txt"
            echo -e "[${BLUE}INFO${NC}] Debug: displaying file contents for combined list"
            head -n 5 "$TEMP_DIR/combined_sorted.txt"
        fi
        
        # Find common words between the lists
        # comm works by comparing two sorted lists, so both need to be properly sorted
        comm -12 "$TEMP_DIR/main_sorted.txt" "$TEMP_DIR/combined_sorted.txt" > "$TEMP_DIR/intersection.txt"
        
        # Count how many common words were found
        local common_count=$(wc -l < "$TEMP_DIR/intersection.txt")
        echo -e "[${BLUE}INFO${NC}] Found $common_count words common to both lists"
        
        # Process the results according to format options
        > "$output"  # Initialize the output file
        
        # Check if we have append/prepend options active
        local append_str="${APPEND_STRING}"
        local prepend_str="${PREPEND_STRING}"
        local using_special_format=0
        
        if [[ -n "$append_str" || -n "$prepend_str" ]]; then
            using_special_format=1
            echo -e "[${BLUE}INFO${NC}] Applying prepend/append to intersection results"
        fi
        
        # Apply formatting to each common word
        if [[ $common_count -gt 0 ]]; then
            while IFS= read -r word; do
                if [[ "$using_special_format" -eq 1 ]]; then
                    # Apply prepend/append only once per word
                    echo "${prepend_str}${word}${append_str}" >> "$output"
                else
                    # Just use the original word without formatting
                    echo "${word}" >> "$output"
                fi
            done < "$TEMP_DIR/intersection.txt"
        fi
        
        # If custom separator was specified, acknowledge it (but don't double-apply words)
        if [[ "$COMBINE_SEPARATOR" != "_" && $common_count -gt 0 ]]; then
            echo -e "[${BLUE}INFO${NC}] Note: custom separator '$COMBINE_SEPARATOR' is not used in intersection mode"
        fi
    fi
}

# Print the tool header
print_header

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--directory) DIRECTORY="$2"; shift ;;
        -o|--output) OUTPUT="$2"; shift ;;
        -k|--keyword) KEYWORD="$2"; shift ;;
        -c|--case-sensitive) CASE_SENSITIVE=1 ;;
        -b|--backup) BACKUP=1 ;;
        -v|--verbose) VERBOSE=1 ;;
        -r|--regex) REGEX_MODE=1 ;;
        -j|--jobs) MAX_THREADS="$2"; shift ;;
        -e|--extensions) ONLY_EXTENSIONS="$2"; shift ;;
        -i|--ignore) IGNORE_EXTENSIONS="$2"; shift ;;
        --min-length) MIN_LENGTH="$2"; shift ;;
        --max-length) MAX_LENGTH="$2"; shift ;;
        --combine-min-length) COMBINE_MIN_LENGTH="$2"; shift ;;
        --combine-max-length) COMBINE_MAX_LENGTH="$2"; shift ;;
        --remove-numbers) REMOVE_NUMBERS=1 ;;
        --remove-special) REMOVE_SPECIAL=1 ;;
        --remove-chars) REMOVE_CHARS="$2"; shift ;;
        --no-binary-check) SKIP_BINARY=0 ;;
        --cross-combine) CROSS_COMBINE=1; PAIR_COMBINE=0 ;;
        --pair-combine) PAIR_COMBINE=1; CROSS_COMBINE=0; CYCLE_COMBINE=0 ;;
        --pair-combine-cycle) PAIR_COMBINE=1; CROSS_COMBINE=0; CYCLE_COMBINE=1 ;;
        --lowercase) FORCE_LOWERCASE=1 ;;
        --combine-sep) COMBINE_SEPARATOR="$2"; shift ;;
        --combine) COMBINE_FILES="$2"; COMBINE_LISTS=1; shift ;;
        --combine-mode) 
            echo -e "[${YELLOW}WARNING${NC}] '--combine-mode' option is deprecated. Using intersection (AND) mode by default."
            COMBINE_MODE="AND"
            shift ;;
        --append) APPEND_STRING="$2"; shift ;;
        --prepend) PREPEND_STRING="$2"; shift ;;
        --replace) 
            REPLACE_PATTERN="${2%%:*}"
            REPLACE_WITH="${2#*:}"
            shift 
            ;;
        -h|--help) show_usage; exit 0 ;;
        -*)
            echo -e "[${RED}ERROR${NC}] Unknown parameter: $1"
            echo -e "[${BLUE}INFO${NC}] Did you mean one of these?"
            
            # Check for similar options to suggest
            declare -a possible_options=("-d" "--directory" "-o" "--output" "-k" "--keyword" 
                                        "-c" "--case-sensitive" "-b" "--backup" "-v" "--verbose" 
                                        "-r" "--regex" "-j" "--jobs" "-e" "--extensions" 
                                        "-i" "--ignore" "--min-length" "--max-length" "--remove-numbers" 
                                        "--remove-special" "--no-binary-check" "--cross-combine" 
                                        "--pair-combine" "--pair-combine-cycle"
                                        "--lowercase" "--combine-sep" "--combine" "--combine-mode"
                                        "--append" "--prepend" "--replace" "-h" "--help")
            
            # Print suggestions based on similarity
            for opt in "${possible_options[@]}"; do
                if [[ "$1" == "$opt"* || "${1#-}" == "${opt#-}"* ]]; then
                    echo -e "    $opt"
                fi
            done
            
            show_usage
            exit 1 
            ;;
        *) echo -e "[${RED}ERROR${NC}] Unknown parameter: $1"; show_usage; exit 1 ;;
    esac
    shift
done

# Check for required arguments
if [[ -z "$DIRECTORY" || -z "$OUTPUT" || -z "$KEYWORD" ]]; then
    echo -e "[${RED}ERROR${NC}] Missing required arguments!"
    show_usage
    exit 1
fi

# Verify directory exists
if [[ ! -d "$DIRECTORY" ]]; then
    echo -e "[${RED}ERROR${NC}] Directory '$DIRECTORY' does not exist!"
    exit 1
fi

# Verify permission to read directory
if [[ ! -r "$DIRECTORY" ]]; then
    echo -e "[${YELLOW}WARNING${NC}] Insufficient permissions to read '$DIRECTORY'. Will try with sudo."
    if ! command_exists sudo; then
        echo -e "[${RED}ERROR${NC}] Sudo is not available. Please run with sufficient permissions."
        exit 1
    fi
    NEED_SUDO=1
else
    NEED_SUDO=0
fi

# Ensure the output directory exists
OUTPUT_DIR=$(dirname "$OUTPUT")
if [[ ! -d "$OUTPUT_DIR" && "$OUTPUT_DIR" != "." ]]; then
    echo -e "[${BLUE}INFO${NC}] Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    if [[ $? -ne 0 ]]; then
        echo -e "[${RED}ERROR${NC}] Failed to create output directory: $OUTPUT_DIR"
        exit 1
    fi
fi

# Check if output file exists and create backup if needed
if [[ -f "$OUTPUT" ]]; then
    if [[ "$BACKUP" -eq 1 ]]; then
        BACKUP_FILE="${OUTPUT}.$(date +%Y%m%d%H%M%S).bak"
        echo -e "[${BLUE}INFO${NC}] Creating backup of existing output file to '$BACKUP_FILE'"
        cp "$OUTPUT" "$BACKUP_FILE"
        if [[ $? -ne 0 ]]; then
            echo -e "[${RED}ERROR${NC}] Failed to create backup!"
            exit 1
        fi
    else
        echo -e "[${YELLOW}WARNING${NC}] Output file '$OUTPUT' exists and will be overwritten."
        echo -e "          Use -b or --backup to create a backup first."
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "[${BLUE}INFO${NC}] Operation cancelled."
            exit 0
        fi
    fi
fi

# Check for required commands
for cmd in grep sed awk sort find; do
    if ! command_exists $cmd; then
        echo -e "[${RED}ERROR${NC}] Required command '$cmd' not found!"
        exit 1
    fi
done

# Build a list of files to process
echo -e "[${GREEN}+${NC}] Scanning '$DIRECTORY' for dictionary files..."

# Function to scan with real-time feedback
scan_with_feedback() {
    local dir="$1"
    local output="$2"
    local need_sudo="$3"
    local found_files=0
    local cmd_prefix=""
    
    # Use sudo if needed
    if [[ "$need_sudo" -eq 1 ]]; then
        cmd_prefix="sudo "
    fi
    
    # Create a temporary fifo for communication
    local fifo="$TEMP_DIR/scan_fifo"
    mkfifo "$fifo"
    
    # Start find in background, sending filenames to the fifo
    ${cmd_prefix}find "$dir" -type f -not -path "*/\.*" > "$fifo" &
    find_pid=$!
    
    # Start reading from fifo and update count in real-time
    > "$output"
    while IFS= read -r file; do
        echo "$file" >> "$output"
        ((found_files++))
        # Update only every 100 files to avoid slowing down
        if (( found_files % 100 == 0 )); then
            printf "\r${GREEN}[+]${NC} Found %d files..." "$found_files"
        fi
    done < "$fifo"
    
    # Check if find command completed successfully
    wait $find_pid
    
    # Clean up fifo
    rm -f "$fifo"
    
    # Final update
    printf "\r${GREEN}[+]${NC} Found %d files                      \n" "$found_files"
}

# Execute scan with feedback
FILE_LIST="$TEMP_DIR/files.list"
scan_with_feedback "$DIRECTORY" "$FILE_LIST" "$NEED_SUDO"

# Filter files by extension if specified
if [[ -n "$ONLY_EXTENSIONS" ]]; then
    echo -e "[${BLUE}INFO${NC}] Filtering files with extensions: $ONLY_EXTENSIONS"
    ext_pattern=$(echo "$ONLY_EXTENSIONS" | sed 's/,/\\|/g')
    grep -E "\\.(${ext_pattern})$" "$FILE_LIST" > "$TEMP_DIR/filtered_files.list"
    mv "$TEMP_DIR/filtered_files.list" "$FILE_LIST"
fi

# Ignore files by extension if specified
if [[ -n "$IGNORE_EXTENSIONS" ]]; then
    echo -e "[${BLUE}INFO${NC}] Ignoring files with extensions: $IGNORE_EXTENSIONS"
    ext_pattern=$(echo "$IGNORE_EXTENSIONS" | sed 's/,/\\|/g')
    grep -v -E "\\.(${ext_pattern})$" "$FILE_LIST" > "$TEMP_DIR/filtered_files.list"
    mv "$TEMP_DIR/filtered_files.list" "$FILE_LIST"
fi

# Get file count and size information
FILE_COUNT=$(wc -l < "$FILE_LIST")
if [[ "$FILE_COUNT" -eq 0 ]]; then
    echo -e "[${RED}ERROR${NC}] No files found to process!"
    exit 1
fi

# Calculate total size
TOTAL_SIZE=0
while read -r file; do
    if [[ "$NEED_SUDO" -eq 1 ]]; then
        size=$(sudo stat -c %s "$file" 2>/dev/null || echo 0)
    else
        size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    fi
    TOTAL_SIZE=$((TOTAL_SIZE + size))
done < "$FILE_LIST"

echo -e "[${GREEN}+${NC}] Found $FILE_COUNT files to process ($(format_size $TOTAL_SIZE))"

# Build the grep command based on options
if [[ "$REGEX_MODE" -eq 1 ]]; then
    echo -e "[${BLUE}INFO${NC}] Using regex pattern mode for keyword: $KEYWORD"
    GREP_PATTERN="$KEYWORD"
else
    echo -e "[${BLUE}INFO${NC}] Filtering words starting with keyword: $KEYWORD"
    GREP_PATTERN="^$KEYWORD"
fi

if [[ "$CASE_SENSITIVE" -eq 1 ]]; then
    GREP_OPTS="-h"
    echo -e "[${BLUE}INFO${NC}] Using case-sensitive matching"
else
    GREP_OPTS="-ih"
    echo -e "[${BLUE}INFO${NC}] Using case-insensitive matching"
fi

print_section_header "Processing Dictionary Files"

# Process files in chunks
PROCESSED=0
OUTFILE="$TEMP_DIR/processed.txt"
touch "$OUTFILE"

# Function to process a file
process_file() {
    local file=$1
    local output=$2
    local pattern=$3
    local grep_opts=$4
    local temp_file="${TEMP_DIR}/tmp_$(basename "$file").txt"
    
    # Use sudo if needed
    if [[ "$NEED_SUDO" -eq 1 ]]; then
        sudo grep $grep_opts "$pattern" "$file" 2>/dev/null > "$temp_file"
    else
        grep $grep_opts "$pattern" "$file" 2>/dev/null > "$temp_file"
    fi
    
    # If file is not empty, process it
    if [[ -s "$temp_file" ]]; then
        cat "$temp_file" >> "$output"
    fi
    
    rm -f "$temp_file"
}

export -f process_file

# Create a semaphore to limit parallel jobs
SEMAPHORE="$TEMP_DIR/semaphore"
mkfifo "$SEMAPHORE"
exec 3<>"$SEMAPHORE"

# Initialize the semaphore with MAX_THREADS tokens
for ((i=1; i<=MAX_THREADS; i++)); do
    echo >&3
done

# Array to collect current progress information globally 
declare -A PROGRESS_INFO
PROGRESS_INFO["total"]="$FILE_COUNT"
PROGRESS_INFO["current"]="0"
TOTAL_FILE_COUNT=$FILE_COUNT  # Store total for reference even if changed

# Process files in parallel with appropriate progress tracking
export PROGRESS_LOCK="$TEMP_DIR/progress.lock"
echo "0" > "$PROGRESS_LOCK"  # Initialize progress counter
export TOTAL_FILES="$FILE_COUNT"
export VERBOSE_MODE="$VERBOSE"
export SKIP_BINARY_MODE="$SKIP_BINARY"

# Export functions for parallel processing
export -f show_progress is_binary_file

# Directly process files with a more efficient approach
process_file_with_progress() {
    local file="$1"
    local outfile="$2"
    local pattern="$3"
    local grep_opts="$4"
    local temp_file="$TEMP_DIR/tmp_$(basename "$file").txt"
    
    # Skip binary files if enabled
    if [[ "$SKIP_BINARY_MODE" -eq 1 ]] && is_binary_file "$file"; then
        if [[ "$VERBOSE_MODE" -eq 1 ]]; then
            echo -e "\r[SKIP] Skipping binary file: $file"
        fi
    else
        # Process the file
        local binary_opt=""
        # If binary check is disabled, treat all files as text with -a option
        if [[ "$SKIP_BINARY_MODE" -eq 0 ]]; then
            binary_opt="-a"
        fi
        
        if [[ "$NEED_SUDO" -eq 1 ]]; then
            sudo grep $binary_opt $grep_opts "$pattern" "$file" 2>/dev/null > "$temp_file"
        else
            grep $binary_opt $grep_opts "$pattern" "$file" 2>/dev/null > "$temp_file"
        fi
        
        # If file is not empty, append to output
        if [[ -s "$temp_file" ]]; then
            cat "$temp_file" >> "$outfile"
        fi
        
        rm -f "$temp_file"
    fi
    
    # Update progress - critical section with atomic update
    {
        flock -x 200
        local current_progress=$(cat "$PROGRESS_LOCK")
        current_progress=$((current_progress + 1))
        echo "$current_progress" > "$PROGRESS_LOCK"
        
        # Show progress update based on file count
        if (( TOTAL_FILES < 20 )) || (( current_progress % 5 == 0 )) || 
           (( current_progress == 1 )) || (( current_progress == TOTAL_FILES )); then
            if [[ "$VERBOSE_MODE" -eq 1 ]]; then
                echo -e "\r[INFO] Processed: $file ($current_progress/$TOTAL_FILES)"
            fi
            show_progress "$current_progress" "$TOTAL_FILES"
        fi
    } 200>"$TEMP_DIR/progress.lock.file"
}

export -f process_file_with_progress

# Process files with parallelism
while read -r file; do
    # Wait for a token from the semaphore
    read -u 3
    
    (
        process_file_with_progress "$file" "$OUTFILE" "$GREP_PATTERN" "$GREP_OPTS"
        
        # Return the token to the semaphore
        echo >&3
    ) &
    
done < "$FILE_LIST"

# Wait for all background jobs to finish
wait

# Close the semaphore
exec 3>&-

echo -e "\n"
print_section_header "Post-Processing Results"

# Apply post-processing to the combined output
POST_PROCESSING_CMDS=""

echo -e "[${BLUE}INFO${NC}] Applying case unification (preserving only one variant per word)"

# Count words for progress bar
WORD_COUNT=$(wc -l < "$OUTFILE")
if [[ $WORD_COUNT -eq 0 ]]; then
    echo -e "[${YELLOW}WARNING${NC}] No words to process for case unification."
    touch "$TEMP_DIR/case_unified.txt"
else
    # Step 1: Create case-insensitive mapping
    echo -ne "[${BLUE}INFO${NC}] Step 1/3: Creating case-insensitive map..."
    > "$TEMP_DIR/word_map.txt"
    PROCESSED=0
    
    # Use a more efficient approach with awk for better performance with large files
    # This creates the mapping in a single pass without calling external processes for each line
    awk '
        BEGIN { FS=""; count=0; total='$WORD_COUNT'; last_update=0; seen_map[""] = 1; }
        {
            if (length($0) > 0) {
                # Create lowercase version directly in awk
                original = $0;
                lower = "";
                for (i=1; i<=length(original); i++) {
                    c = substr(original, i, 1);
                    if (c >= "A" && c <= "Z") {
                        # Convert to lowercase by adding 32 to ASCII value
                        c = sprintf("%c", ord(c) + 32);
                    }
                    lower = lower c;
                }
                
                # Output the mapping
                print original "|" lower;
                
                # Update progress
                count++;
                if (count % 500 == 0 || count == total) {
                    percent = int(count * 100 / total);
                    # Only update every 500 words or at the end
                    if (count % 500 == 0 || count == total) {
                        printf("\r['$BLUE'INFO'$NC'] Step 1/3: Creating case-insensitive map... %d%% (%d/%d)", percent, count, total) > "/dev/stderr";
                    }
                }
            }
        }
        # ASCII to ord conversion function
        function ord(c) {
            return index("@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz", c) + 63;
        }
    ' "$OUTFILE" > "$TEMP_DIR/word_map.txt"
    PROCESSED=$WORD_COUNT
    echo # New line after progress bar
    
    # Step 2: Sort by lowercase variant
    echo -e "[${BLUE}INFO${NC}] Step 2/3: Sorting variants..."
    sort -t '|' -k2 "$TEMP_DIR/word_map.txt" > "$TEMP_DIR/sorted_map.txt"
    
    # Step 3: Extract only the first occurrence of each case-insensitive variant
    echo -ne "[${BLUE}INFO${NC}] Step 3/3: Unifying variants..."
    > "$TEMP_DIR/case_unified.txt"
    
    # More reliable approach using a simpler algorithm to avoid syntax errors
    prev_lower=""
    PROCESSED=0
    TOTAL_WORDS=$(wc -l < "$TEMP_DIR/sorted_map.txt")
    
    while IFS='|' read -r original lower; do
        # Compare entire lowercase string to ensure we only keep one variant
        if [[ "$lower" != "$prev_lower" ]]; then
            echo "$original" >> "$TEMP_DIR/case_unified.txt"
            prev_lower="$lower"
        fi
        
        ((PROCESSED++))
        # Update progress bar every 500 words
        if (( PROCESSED % 500 == 0 )) || (( PROCESSED == TOTAL_WORDS )); then
            PERCENTAGE=$((PROCESSED * 100 / TOTAL_WORDS))
            printf "\r[${BLUE}INFO${NC}] Step 3/3: Unifying variants... %d%% (%d/%d)" "$PERCENTAGE" "$PROCESSED" "$TOTAL_WORDS"
        fi
    done < "$TEMP_DIR/sorted_map.txt"
    echo # New line after progress bar
fi

# Sort the output for consistency
sort "$TEMP_DIR/case_unified.txt" > "$TEMP_DIR/sorted_unified.txt"

# Replace the output file with case-unified version
mv "$TEMP_DIR/sorted_unified.txt" "$OUTFILE"

# Apply length and character filters early in the process, right after case unification
if [[ "$MIN_LENGTH" -gt 0 || "$MAX_LENGTH" -gt 0 || "$REMOVE_NUMBERS" -eq 1 || "$REMOVE_SPECIAL" -eq 1 || -n "$REMOVE_CHARS" ]]; then
    echo -e "[${BLUE}INFO${NC}] Applying early filters to main wordlist"
    
    # Create a temporary file to store filtered output
    FILTERED_MAIN="$TEMP_DIR/filtered_main.txt"
    
    # Apply the filters to the main file
    FILTERED_COUNT=$(apply_filters "$OUTFILE" "$FILTERED_MAIN" \
                    "$MIN_LENGTH" "$MAX_LENGTH" \
                    "$REMOVE_NUMBERS" "$REMOVE_SPECIAL" "$REMOVE_CHARS" \
                    "Main wordlist")
    
    # Replace the output with the filtered version
    echo -e "[${BLUE}INFO${NC}] Filtered main wordlist from $(wc -l < "$OUTFILE") to $FILTERED_COUNT words"
    mv "$FILTERED_MAIN" "$OUTFILE"
fi

# Save a clean copy of the filtered case-unified words BEFORE applying append/prepend modifiers
# We'll use this for intersection operations to avoid mismatches
cp "$OUTFILE" "$TEMP_DIR/clean_unified.txt"

# Remove lines after certain delimiters
POST_PROCESSING_CMDS+="sed 's/[.,\/\\:;].*$//' | "

# If we need to replace patterns
if [[ -n "$REPLACE_PATTERN" ]]; then
    echo -e "[${BLUE}INFO${NC}] Replacing '$REPLACE_PATTERN' with '$REPLACE_WITH' in each word"
    POST_PROCESSING_CMDS+="sed 's/$REPLACE_PATTERN/$REPLACE_WITH/g' | "
fi

# Check if we need to delay append/prepend for intersection operations
DELAY_MODIFIERS=0
if [[ "$COMBINE_LISTS" -eq 1 && "$CROSS_COMBINE" -ne 1 ]]; then
    DELAY_MODIFIERS=1
    if [[ -n "$PREPEND_STRING" || -n "$APPEND_STRING" ]]; then
        echo -e "[${BLUE}INFO${NC}] Will apply prepend/append after intersection for correct matching"
    fi
fi

# Apply prepend if appropriate
if [[ -n "$PREPEND_STRING" ]]; then
    if [[ "$CROSS_COMBINE" -eq 1 && "$COMBINE_LISTS" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] Prepend will be applied during cross combination"
    elif [[ "$DELAY_MODIFIERS" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] Prepend will be applied after intersection"
        # Don't add to POST_PROCESSING_CMDS yet, we'll apply it later
    else
        echo -e "[${BLUE}INFO${NC}] Prepending '$PREPEND_STRING' to each word"
        # Uso di awk invece di sed per evitare problemi di escape con caratteri speciali
        POST_PROCESSING_CMDS+="awk '{print \"$PREPEND_STRING\" \$0}' | "
    fi
fi

# Apply append if appropriate
if [[ -n "$APPEND_STRING" ]]; then
    if [[ "$CROSS_COMBINE" -eq 1 && "$COMBINE_LISTS" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] Append will be applied during cross combination"
    elif [[ "$DELAY_MODIFIERS" -eq 1 ]]; then
        echo -e "[${BLUE}INFO${NC}] Append will be applied after intersection"
        # Don't add to POST_PROCESSING_CMDS yet, we'll apply it later
    else
        echo -e "[${BLUE}INFO${NC}] Appending '$APPEND_STRING' to each word"
        # Uso di awk invece di sed per evitare problemi di escape con caratteri speciali
        
        # Check if APPEND_STRING contains multiple extensions separated by spaces
        if [[ "$APPEND_STRING" == *" "* ]]; then
            echo -e "[${BLUE}INFO${NC}] Multiple extensions detected, generating variants for each extension"
            # Split APPEND_STRING by spaces and generate a variant for each extension
            POST_PROCESSING_CMDS+="awk '{word=\$0; "
            # Use split to handle multiple extensions
            POST_PROCESSING_CMDS+="split(\"$APPEND_STRING\", extensions, \" \"); "
            POST_PROCESSING_CMDS+="for(i in extensions) { "
            POST_PROCESSING_CMDS+="if (extensions[i] != \"\") print word extensions[i]; "
            POST_PROCESSING_CMDS+="}} ' | "
        else
            # Single extension, use the original logic
            POST_PROCESSING_CMDS+="awk '{print \$0 \"$APPEND_STRING\"}' | "
        fi
    fi
fi

# Number and character filtering is now done early in the process
# We don't apply these filters in post-processing anymore

# MIN_LENGTH and MAX_LENGTH are applied directly at the beginning of the process
# The filters in post-processing have been moved

# Convert to lowercase if requested
if [[ "$FORCE_LOWERCASE" -eq 1 ]]; then
    echo -e "[${BLUE}INFO${NC}] Forcing all output to lowercase"
    POST_PROCESSING_CMDS+="awk '{ print tolower(\$0) }' | "
fi

# Finish with sort and unique
POST_PROCESSING_CMDS+="sort -u"

# Execute the post-processing commands
if [[ -s "$OUTFILE" ]]; then
    echo -e "[${BLUE}INFO${NC}] Applying post-processing filters..."
    eval "cat \"$OUTFILE\" | $POST_PROCESSING_CMDS > \"$TEMP_DIR/processed_output.txt\""
    
    # Handle combination of lists
    if [[ "$COMBINE_LISTS" -eq 1 ]]; then
        echo -e "[${GREEN}+${NC}] Combining with additional word lists..."
        
        # Create a combined file from all the additional lists
        COMBINED_TEMP="$TEMP_DIR/combined_lists.txt"
        touch "$COMBINED_TEMP"
        
        IFS=',' read -ra LIST_FILES <<< "$COMBINE_FILES"
        for list_file in "${LIST_FILES[@]}"; do
            if [[ ! -f "$list_file" ]]; then
                echo -e "[${YELLOW}WARNING${NC}] Combine list file not found: $list_file"
                continue
            fi
            
            echo -e "[${BLUE}INFO${NC}] Adding words from: $list_file"
            cat "$list_file" >> "$COMBINED_TEMP"
        done
        
        if [[ -s "$COMBINED_TEMP" ]]; then
            # Apply length and character filters to the combined list before combining
            FILTERED_COMBINED_TEMP="$TEMP_DIR/filtered_combined_lists.txt"
            
            # Apply filters to the combined list if specified
            COMBINED_COUNT=$(apply_filters "$COMBINED_TEMP" "$FILTERED_COMBINED_TEMP" \
                             "$COMBINE_MIN_LENGTH" "$COMBINE_MAX_LENGTH" \
                             "$REMOVE_NUMBERS" "$REMOVE_SPECIAL" "$REMOVE_CHARS" \
                             "Secondary lists")
                             
            # Apply the combine operation using the filtered combined list
            FINAL_OUTPUT="$TEMP_DIR/final_output.txt"
            combine_lists "$TEMP_DIR/processed_output.txt" "$FILTERED_COMBINED_TEMP" "$COMBINE_MODE" "$FINAL_OUTPUT"
            
            # Count the original and final results
            ORIG_COUNT=$(wc -l < "$TEMP_DIR/processed_output.txt")
            FINAL_COUNT=$(wc -l < "$FINAL_OUTPUT")
            
            # Note: We don't need to filter again here,
            # since filtering is already done before combination
            # This preserves any appended/prepended strings or separators
            
            # Move the final output to the specified output file
            mv "$FINAL_OUTPUT" "$OUTPUT"
            
            echo -e "[${BLUE}INFO${NC}] Original list: $ORIG_COUNT words, Combined lists: $COMBINED_COUNT words"
            if [[ "$CROSS_COMBINE" -eq 1 ]]; then
                echo -e "[${BLUE}INFO${NC}] After cross-combination with separator '$COMBINE_SEPARATOR': $FINAL_COUNT words"
            else
                echo -e "[${BLUE}INFO${NC}] After intersection combination: $FINAL_COUNT words"
            fi
        else
            echo -e "[${YELLOW}WARNING${NC}] No valid combine files found, using original results."
            mv "$TEMP_DIR/processed_output.txt" "$OUTPUT"
        fi
    else
        # Just use the processed output
        mv "$TEMP_DIR/processed_output.txt" "$OUTPUT"
    fi
    
    RESULT_COUNT=$(wc -l < "$OUTPUT")
    OUTPUT_SIZE=$(stat -c %s "$OUTPUT" 2>/dev/null || echo 0)
    AVG_WORD_LEN=$(awk '{ sum += length; } END { if(NR > 0) printf "%.1f", sum/NR; else print "0"; }' "$OUTPUT")
    
    # Display statistics in a box
    echo
    print_section_header "Results Summary"
    
    # Prepare stats for the box
    STATS=(
        "Output file: $OUTPUT"
        "Total entries: ${BOLD}$RESULT_COUNT${NC} unique words"
        "File size: $(format_size $OUTPUT_SIZE)"
        "Average word length: ${BOLD}$AVG_WORD_LEN${NC} characters"
    )
    
    # Add case info
    if [[ "$FORCE_LOWERCASE" -eq 1 ]]; then
        STATS+=("Case format: Forced lowercase")
    else
        STATS+=("Case format: Original case preserved")
    fi
    
    # Add combine stats if applicable
    if [[ "$COMBINE_LISTS" -eq 1 && "$RESULT_COUNT" -gt 0 ]]; then
        if [[ "$CROSS_COMBINE" -eq 1 ]]; then
            STATS+=("Combination: Cross-combined with separator '$COMBINE_SEPARATOR'")
        else
            STATS+=("Combination: Intersection mode (${RESULT_COUNT} words)")
        fi
    fi
    
    # Print statistics box
    print_stats_box "Dictionary Statistics" "${STATS[@]}"
    
    if [[ "$RESULT_COUNT" -eq 0 ]]; then
        echo -e "\n[${YELLOW}WARNING${NC}] No words matched your criteria!"
    elif [[ "$RESULT_COUNT" -lt 10 ]]; then
        echo -e "\n[${YELLOW}WARNING${NC}] Very few words matched your criteria. Consider relaxing filters."
    fi
    
    # Show the first few lines if results found
    if [[ "$RESULT_COUNT" -gt 0 ]]; then
        echo -e "\n[${BLUE}INFO${NC}] Preview of results (first 5 entries):"
        head -n 5 "$OUTPUT" | sed 's/^/    /'
    fi
else
    echo -e "[${RED}ERROR${NC}] No matches found for your criteria!"
    exit 1
fi

# Clean up
rm -rf "${TEMP_DIR}"

# Display completion message with fancy box
echo
print_stats_box "Process Complete" "Dictionary generation completed successfully!" "Words have been saved to: $OUTPUT"
echo
