import os

# Define the paths
rules_folder = os.path.join(os.getcwd(), "rules")
antiviruspro_file = os.path.join(rules_folder, "antiviruspro.yar")
falsepositives_file = os.path.join(rules_folder, "falsepositives.yar")
antivirusprofullyfixed_file = os.path.join(rules_folder, "antivirusprofullyfixed.yar")
unique_rules_file = os.path.join(os.getcwd(), "unique_rules.txt")

def read_unique_rules():
    """Read unique rule names from the file (one rule per line)."""
    with open(unique_rules_file, 'r') as file:
        return set(line.strip() for line in file.readlines())

def separate_rules():
    """Separate the YARA rules into false positives and fixed ones."""
    unique_rules = read_unique_rules()

    with open(antiviruspro_file, 'r') as file:
        lines = file.readlines()

    rule_content = []
    is_in_rule = False
    current_rule_name = None
    false_positive_rules = []
    fully_fixed_rules = []

    for line in lines:
        if line.strip().startswith("rule") and "{" in line:
            if current_rule_name:
                # Add the previous rule to the corresponding list
                if current_rule_name in unique_rules:
                    false_positive_rules.append("".join(rule_content))
                else:
                    fully_fixed_rules.append("".join(rule_content))
            
            # Start a new rule
            rule_content = [line]
            current_rule_name = line.split("rule")[1].split("{")[0].strip()
            is_in_rule = True
        elif is_in_rule:
            # Exclude lines containing condition:
            if line.strip().startswith("condition:") or line.strip() == "}":
                rule_content.append(line)
                if "}" in line:
                    is_in_rule = False
            else:
                rule_content.append(line)

    # Add the last rule
    if current_rule_name:
        if current_rule_name in unique_rules:
            false_positive_rules.append("".join(rule_content))
        else:
            fully_fixed_rules.append("".join(rule_content))

    # Save the separated rules to respective files
    with open(falsepositives_file, 'w') as file:
        file.writelines(false_positive_rules)

    with open(antivirusprofullyfixed_file, 'w') as file:
        file.writelines(fully_fixed_rules)

    print(f"False positives saved to {falsepositives_file}")
    print(f"Fully fixed rules saved to {antivirusprofullyfixed_file}")

if __name__ == "__main__":
    separate_rules()
