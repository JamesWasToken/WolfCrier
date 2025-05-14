import json,time,dotenv,os,ipaddress,datetime
from censys.asm import Risks, HostsAssets
from collections import defaultdict

quiet = True
UseOld = True

dotenv.load_dotenv()
asm_api = os.getenv('ASM_API')
r = Risks(asm_api)
h = HostsAssets(asm_api)

class NoJsonFilesError(Exception):
    """Custom exception for when no JSON files are found."""
    pass

def get_most_recent_json(folder_path):
    # List all .json files in the directory
    json_files = [f for f in os.listdir(folder_path) if f.endswith('.json')]
    
    # Raise an exception if no JSON files are found
    if not json_files:
        raise NoJsonFilesError("No JSON files found in the specified directory.")

    # Find the most recent JSON file
    most_recent_file = max(
        json_files,
        key=lambda f: datetime.datetime.strptime(f[:-5], '%a %b %d %H:%M:%S %Y')
    )
    
    # Generate the full path to the most recent JSON file
    most_recent_file_path = os.path.join(folder_path, most_recent_file)
    
    return most_recent_file_path

if not UseOld:
    last_edit = os.path.getmtime("./last.json")
    t24 = (datetime.datetime.now()-datetime.timedelta(hours=24)).timestamp()
    # New lines for calculation and output
    time_diff = datetime.datetime.now().timestamp() - last_edit
    hours, minutes = divmod(time_diff, 3600)
    print(f"It has been {int(hours)} hours and {int(minutes // 60)} minutes since last data was set.")
    if last_edit < t24:
        os.system(f'mv ./last.json ./storage/"{time.ctime(last_edit)}.json"')
        os.system('mv ./current.json ./last.json')
        # Load yesterday's and today's formatted JSON output
    with open('last.json', 'r') as f:
        yesterdays_output = json.load(f)
else:
    # Example usage
    folder_path = './storage'  # Update with your folder path
    try:
        recent_json_path = get_most_recent_json(folder_path)
        print(f"The most recently named JSON file is: {recent_json_path}")
        last_edit = os.path.getmtime(recent_json_path)
        t24 = (datetime.datetime.now()-datetime.timedelta(hours=24)).timestamp()
        # New lines for calculation and output
        time_diff = datetime.datetime.now().timestamp() - last_edit
        hours, minutes = divmod(time_diff, 3600)
        print(f"It has been {int(hours)} hours and {int(minutes // 60)} minutes since named data was set.")
        # You can now open the JSON file as needed
        with open(recent_json_path, 'r') as json_file:
            yesterdays_output = json.load(json_file)  # Assuming you want to load it as a dictionary
            # Process the json_data as needed
    except NoJsonFilesError as e:
        print(e)
    except Exception as e:
        print(f"An error occurred: {e}")
   
api_response = r.get_risk_instances()
#if not quiet:
#    print(f"\"api_response\": {api_response},")

def map_tags(output_dict):
    for assest_id in output_dict.keys():
        if assest_id not in tags_mapping.keys():
            tagz = []
            isdomain = False
            dead = False
            try:
                ip_tag = str(ipaddress.IPv4Address(assest_id))
            except Exception as e:
                isdomain = True
                #tags_mapping[assest_id] = [f"Error: {e}"]
            if not isdomain:
                try:
                    host = h.get_asset_by_id(ip_tag)
                    if not quiet:
                        print(f"\"host1\": {host},")
                except:
                    dead = True
                if dead:
                    tags_mapping[assest_id] = ["Disassociated"]
                else:
                    try:
                        for tag in host['tags']:
                            tagz.append(tag['name'])
                    except Exception as e:
                        tagz = [f'Error: {e}']
                    tags_mapping[assest_id] = tagz
            else:
                tags_mapping[assest_id] = [""]
    return tags_mapping

def map_old_tags(olddict,tags_mapping):
    for asset_id in olddict.keys():
        if asset_id not in tags_mapping.keys():
            tagz = []
            isdomain = False
            dead = False
            try:
                ip_tag = str(ipaddress.IPv4Address(asset_id))
            except:
                isdomain = True
                #tags_mapping[asset_id] = [f"Error: {e}"]
            if not isdomain:
                try:
                    host = h.get_asset_by_id(ip_tag)
                    if not quiet:
                        print(f"\"host2\": {host},")
                except:
                    dead = True
                if dead:
                    tags_mapping[asset_id] = ["Disassociated"]
                else:
                    try:
                        for tag in host['tags']:
                            tagz.append(tag['name'])
                    except Exception as e:
                        tagz = [f'Error: {e}']
                    tags_mapping[asset_id] = tagz
            else:
                tags_mapping[asset_id] = ['']
    return tags_mapping

#with open('all.json','w') as all_risks:
#    json.dump(api_response,all_risks,indent=4,ensure_ascii=False)

# This will hold the final results
output_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

# Process each item in the 'data' list
for item in api_response['risks']:
    context = item['context']
    
    # Determine the type of context
    if context['type'] == 'host':
        # Handle first type of context
        address_key = context['ip']
        vice_place_key = f"{context['service']} ({context['port']})"
        display_name = item['displayName']
        try:
            score = item['cvss_v3']
        except:
            try:
                score = item['cvss_v2']
            except:
                score = 'n/a'
        
        # Separate displayName and extract content inside []
        if '[' in display_name and ']' in display_name:
            base_name, subitem = display_name.split('[')
            base_name = base_name.strip()  # remove trailing spaces
            subitem = subitem.strip('] ')
            value = f"{subitem} ({score})"
        else:
            base_name = display_name
            value = score
        
        # Store the result
        output_dict[address_key][vice_place_key][base_name].append(value)
    
    elif context['type'] == 'domain':
        # Handle second type of context
        location_key = context['domain']
        display_name = item['displayName']
        try:
            score = item['cvss_v3']
        except:
            try:
                score = item['cvss_v2']
            except:
                score = 'n/a'
        
        # Separate displayName and extract content inside []
        if '[' in display_name and ']' in display_name:
            base_name, subitem = display_name.split('[')
            base_name = base_name.strip()  # remove trailing spaces
            subitem = subitem.strip('] ')
            value = f"{subitem} ({score})"
        else:
            base_name = display_name
            value = score

        # Ensure output_dict[location_key][base_name] is a list
        if not isinstance(output_dict[location_key][base_name], list):
            output_dict[location_key][base_name] = []
        
        # Store the result in a list
        output_dict[location_key][base_name].append(value)
    
    elif context['type'] == 'webentity':
        context_key = item['context']['name']
        port_key = item['context']['port']
        #context_key = f"{context_key} ({port_key})"
        display_name = item['displayName']
        vice_place_key = f"HTTP ({port_key})"
        try:
            score = item['cvss_v3']
        except:
            try:
                score = item['cvss_v2']
            except:
                score = 'n/a'
        
        # Separate displayName and extract content inside []
        if '[' in display_name and ']' in display_name:
            base_name, subitem = display_name.split('[')
            base_name = base_name.strip()  # remove trailing spaces
            subitem = subitem.strip('] ')
            key = f"{base_name}"
            value = f"{subitem} ({score})"
        else:
            key = display_name
            value = score

        # Ensure output_dict[location_key][base_name] is a list
        if not isinstance(output_dict[context_key][vice_place_key][key], list):
            output_dict[context_key][vice_place_key][key] = []

        output_dict[context_key][vice_place_key][key].append(value)

output_dict = {k: dict(v) for k, v in output_dict.items()}
output_dict = {k: {vk: dict(vv) if isinstance(vv, defaultdict) else vv for vk, vv in v.items()} for k, v in output_dict.items()}

# Example output
with open("current.json",'w') as risk_file:
    json.dump(output_dict,risk_file,indent=4,ensure_ascii=False)

#exit(1)
### Comparing
#Testing
import json
import pandas as pd

with open('current.json', 'r') as f:
    todays_output = json.load(f)

# Convert the dictionaries to DataFrames
df_yesterday = pd.DataFrame.from_dict(yesterdays_output, orient='index').stack().reset_index()
df_today = pd.DataFrame.from_dict(todays_output, orient='index').stack().reset_index()

# Rename columns for clarity
df_yesterday.columns = ['ID', 'Service', 'Risk']
df_today.columns = ['ID', 'Service', 'Risk']

# Merge the two DataFrames for comparison
comparison_df = pd.merge(df_yesterday, df_today, how='outer', on=['ID', 'Service'], suffixes=('_yesterday', '_today'), indicator=True)

# Keep only the most up-to-date values
comparison_df['Risk'] = comparison_df.apply(lambda row: row['Risk_today'] if pd.notna(row['Risk_today']) else row['Risk_yesterday'], axis=1)

# Add a new "Tags" column based on the key
tags_mapping = {}
tags_mapping = map_tags(output_dict)
tags_mapping = map_old_tags(yesterdays_output,tags_mapping)
with open('tags.json','w') as tag_file:
    json.dump(tags_mapping,tag_file,indent=4,ensure_ascii=False)

# Function to retrieve tags based on key
def get_tags(key):
    return ', '.join(tags_mapping.get(key, []))

comparison_df['Tags'] = comparison_df['ID'].apply(get_tags)

# Hardcoded dict for special tags with specific colors
special_tags = {
    "Disassociated": {"color": "red"},
    # Add more tags with their colors here
}

# Select only the columns you want to keep
comparison_df = comparison_df[['ID', 'Tags', 'Service', 'Risk', '_merge']]

# Example tag ranking dictionary
tag_rank = {
    "Disassociated": -50,
    # Add more tags here as needed
}

# Set a hard-coded value for unknown tags
unknown_tag_value = -100

# Define a function to calculate the sorting value for each row based on its tags
def calculate_tag_value(tag_string):
    if pd.isna(tag_string) or tag_string == '':  # No tags case
        return -9999  # Assign the lowest value to rows with no tags

    tags = tag_string.split(', ')  # Split multiple tags by the delimiter
    tag_values = [tag_rank.get(tag, unknown_tag_value) for tag in tags]  # Get values for each tag, default to unknown_tag_value if not found
    return sum(tag_values)  # Sum the tag values for sorting

# Apply the function to the 'Tags' column to calculate sorting values
comparison_df['tag_value'] = comparison_df['Tags'].apply(calculate_tag_value)

# Define a custom order for the _merge column
merge_order = ['right_only', 'both', 'left_only']

# Convert the _merge column to a Categorical type with the custom order
comparison_df['_merge'] = pd.Categorical(comparison_df['_merge'], categories=merge_order, ordered=True)

# Now sort by _merge, tag_value, and then Service
comparison_df = comparison_df.sort_values(by=['_merge', 'tag_value', 'Service'], ascending=[True, True, True])

# Optionally reset index if desired
comparison_df.reset_index(drop=True, inplace=True)

# Define a function to highlight the rows based on the comparison
def highlight_diff(row):
    num_columns = len(row)
    styles = [''] * num_columns  # Initialize a list of empty styles for each column
    
    # Apply color coding for rows based on '_merge' column
    if row['_merge'] == 'left_only':  # Only in yesterday's data (removed)
        styles = ['background-color: red; color: white'] * num_columns
    elif row['_merge'] == 'right_only':  # Only in today's data (new)
        styles = ['background-color: green; color: white'] * num_columns

    # Highlight specific tags in the "Tags" column (assuming it's the second column)
    tag_list = row['Tags'].split(', ') if pd.notna(row['Tags']) else []
    
    for tag in tag_list:
        if tag in special_tags:
            styles[1] = f'background-color: {special_tags[tag]["color"]}; color: white'  # Apply the tag color to the 'Tags' column
    
    return styles

# Apply the styling function to the DataFrame
styled_df = comparison_df.style.apply(highlight_diff, axis=1)

# Drop the '_merge' column after applying the styling
comparison_df_final = comparison_df.drop('_merge', axis=1)

# Save the styled DataFrame as HTML with custom styles for black background and white text
html_output = styled_df.to_html()

# Add custom CSS for black background, white text, and a specific font (e.g., Arial)
custom_css = """
    <style>
        body {
            background-color: black;
            color: white;
            font-family: sans-serif;  /* Specify the font family */
        }
        table {
            border-collapse: collapse;
            width: 100%;
            font-family: sans-serif;  /* Apply the same font to table content */
        }
        th, td {
            border: 1px solid white;
            padding: 8px;
            font-family: sans-serif;  /* Ensure the font is consistent */
        }
    </style>
"""

# Example title for the HTML page
html_title = f"<h1 style='text-align:center;'>New Risks Since {time.ctime(last_edit)} ({int(hours)} Hours {int(minutes // 60)} Minutes)</h1>"

# Write the final HTML with the custom CSS
with open('comparison_output.html', 'w') as f:
    f.write(custom_css + html_title + html_output)

# Export the final comparison DataFrame to a pretty JSON file
json_output = comparison_df_final.to_dict(orient='records')  # Convert to list of dictionaries
with open('comparison_output.json', 'w') as json_file:
    json.dump(json_output, json_file, indent=4)

print("Comparison complete. Check 'comparison_output.html' for the diff.")

