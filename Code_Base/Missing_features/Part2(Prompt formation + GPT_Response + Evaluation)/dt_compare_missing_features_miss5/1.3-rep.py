import json

def find_failed_responses(log_file_path):
    with open(log_file_path, 'r') as file:
        lines = file.readlines()
    
    failed_lines = []
    for i, line in enumerate(lines):
        if any(keyword in line for keyword in ["Attempt to decode JSON with unexpected mimetype", "429", "500"]):
            failed_lines.append(i + 1)
    
    return failed_lines

def read_new_responses(new_responses_file_path):
    with open(new_responses_file_path, 'r') as infile:
        new_responses = infile.readlines()
    
    return new_responses

def replace_failed_responses(original_file_path, new_responses, failed_lines, output_file_path):
    with open(original_file_path, 'r') as infile:
        original_lines = infile.readlines()
    
    for i, line_num in enumerate(failed_lines):
        if line_num - 1 < len(original_lines) and i < len(new_responses):
            original_lines[line_num - 1] = new_responses[i]
    
    with open(output_file_path, 'w') as outfile:
        outfile.writelines(original_lines)

# Paths to your files
log_file_path = 'dt_compare_missing_features/output/analysis_input_results.jsonl'  # Log file path
original_file_path = 'dt_compare_missing_features/output/analysis_input_results.jsonl'  # Original JSONL file path
new_responses_file_path = 'dt_compare_missing_features/output/analysis_input_fix2_results.jsonl'  # New responses JSONL file path
output_file_path = 'dt_compare_missing_features/output/final_analysis_input_results.jsonl'  # Output JSONL file path

failed_lines = find_failed_responses(log_file_path)
print("Line numbers with failed responses:", failed_lines)
# Read the new responses from the new responses JSONL file
new_responses = read_new_responses(new_responses_file_path)

# Replace the failed responses in the original file and write to a new file
replace_failed_responses(original_file_path, new_responses, failed_lines, output_file_path)

print(f"Updated responses have been written to {output_file_path}")
