import os

# Define the paths for the input and output files
script_dir = os.getcwd()
input_file = os.path.join(script_dir, "false_positives.txt")
output_file = os.path.join(script_dir, "unique_rules.txt")

def extract_unique_rules(rules_part):
    # Split the rules by commas and remove any leading/trailing whitespace
    rules = [rule.strip() for rule in rules_part.split(',')]
    # Use a set to remove duplicates and return as a list
    unique_rules = list(set(rules))
    return unique_rules

def extract_rules_to_file(input_path, output_path):
    # Check if the input file exists
    if not os.path.exists(input_path):
        print(f"Input file not found: {input_path}")
        return

    # Set to store all unique rule names
    all_unique_rules = set()

    # Read and process each line in the input file
    with open(input_path, "r") as file:
        for line in file:
            if "Rules matched:" in line:
                # Split the line by "Rules matched:" to get the rules part
                _, rules_part = line.split("Rules matched:", 1)
                
                # Extract unique rules and add them to the set
                unique_rules = extract_unique_rules(rules_part)
                all_unique_rules.update(unique_rules)

    # Write the unique rules to the output file in alphabetical order
    with open(output_path, "w") as file:
        for rule in sorted(all_unique_rules):
            file.write(rule + "\n")

    print(f"Unique rules saved to {output_path}")

# Run the processing function
if __name__ == "__main__":
    extract_rules_to_file(input_file, output_file)
