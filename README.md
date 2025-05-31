# iis_gen 🛠️ - IIS Tilde Enumeration Dictionary Generator

![GitHub release](https://img.shields.io/github/release/dilan1001/iis_gen.svg) ![GitHub issues](https://img.shields.io/github/issues/dilan1001/iis_gen.svg) ![GitHub stars](https://img.shields.io/github/stars/dilan1001/iis_gen.svg)

Welcome to **iis_gen**, a specialized bash tool designed for creating wordlists that target the IIS tilde enumeration vulnerability. This tool helps penetration testers and security professionals generate optimized dictionaries for discovering hidden files and directories on vulnerable IIS servers.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features

- **Custom Wordlist Generation**: Generate wordlists tailored for IIS servers using the 8.3 short-name disclosure technique.
- **Optimized for Security Testing**: Designed specifically for pentesting, making it a valuable tool for security assessments.
- **Easy to Use**: The script is straightforward and requires minimal setup.
- **Open Source**: Contribute to the project and help improve its functionality.

## Installation

To get started with **iis_gen**, you can download the latest release from the [Releases section](https://github.com/dilan1001/iis_gen/releases). Look for the appropriate file, download it, and execute it on your system.

### Prerequisites

- A Unix-based operating system (Linux, macOS)
- Bash shell
- Basic knowledge of command-line operations

### Steps

1. **Clone the Repository**: You can clone the repository using Git:

   ```bash
   git clone https://github.com/dilan1001/iis_gen.git
   cd iis_gen
   ```

2. **Download the Release**: Alternatively, you can visit the [Releases section](https://github.com/dilan1001/iis_gen/releases) and download the latest version.

3. **Set Permissions**: Make the script executable:

   ```bash
   chmod +x iis_gen.sh
   ```

4. **Run the Script**: Execute the script to generate your wordlist:

   ```bash
   ./iis_gen.sh
   ```

## Usage

Using **iis_gen** is simple. After executing the script, you can specify parameters to customize your wordlist generation.

### Command-Line Options

- `-h, --help`: Display help information.
- `-o, --output`: Specify the output file for the generated wordlist.
- `-l, --length`: Set the maximum length of words in the wordlist.

### Example Command

```bash
./iis_gen.sh -o my_wordlist.txt -l 10
```

This command generates a wordlist saved as `my_wordlist.txt` with a maximum word length of 10 characters.

## Examples

Here are a few examples to illustrate how **iis_gen** can be used effectively:

### Basic Usage

Generate a default wordlist:

```bash
./iis_gen.sh
```

### Custom Output File

Generate a wordlist and save it to a specific file:

```bash
./iis_gen.sh -o custom_list.txt
```

### Specifying Word Length

Generate a wordlist with a specific maximum word length:

```bash
./iis_gen.sh -l 8
```

### Combining Options

You can combine options for more tailored output:

```bash
./iis_gen.sh -o my_custom_list.txt -l 12
```

## Contributing

Contributions are welcome! If you would like to contribute to **iis_gen**, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes.
4. Push your branch to your forked repository.
5. Create a pull request.

Please ensure that your code adheres to the project's coding standards and includes relevant tests.

## License

**iis_gen** is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Support

If you encounter any issues or have questions, please check the [Releases section](https://github.com/dilan1001/iis_gen/releases) for updates. You can also open an issue in the GitHub repository.

---

Thank you for checking out **iis_gen**! We hope this tool aids you in your security assessments and enhances your pentesting toolkit. Happy hacking! 🕵️‍♂️