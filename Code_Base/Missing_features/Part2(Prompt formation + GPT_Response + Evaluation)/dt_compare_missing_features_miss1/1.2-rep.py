import json

def find_failed_responses(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    failed_lines = []
    for i, line in enumerate(lines):
        if any(keyword in line for keyword in ["Attempt to decode JSON with unexpected mimetype", "429", "500"]):
            failed_lines.append(i + 1)
    
    return failed_lines

def extract_failed_responses(input_file_path, output_file_path, failed_lines):
    with open(input_file_path, 'r') as infile, open(output_file_path, 'w') as outfile:
        lines = infile.readlines()
        
        for i in failed_lines:
            # Adjusting for 0-based index
            line_index = i - 1
            if line_index < len(lines):
                outfile.write(lines[line_index])

# Path to your JSONL log file
log_file_path = 'dt_compare_missing_features/output/analysis_input_results.jsonl'
# Path to your input JSONL file
input_file_path = 'dt_compare_missing_features/output/analysis_input.jsonl'
# Path to your output JSONL file
output_file_path = 'dt_compare_missing_features/output/analysis_input_fix2.jsonl'

# Find the line numbers with failed responses
failed_lines = find_failed_responses(log_file_path)
print("Line numbers with failed responses:", failed_lines)
print(len(failed_lines))
# Extract the failed response lines to a new JSONL file
extract_failed_responses(input_file_path, output_file_path, failed_lines)

print(f"Failed responses have been extracted to {output_file_path}")
