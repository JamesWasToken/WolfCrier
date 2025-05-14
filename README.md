# WolfCrier
The newest and up to date WolfCrier. Documentation will be attempted to be kept up to date.

## Documentation

### Documentation: How to Use and Modify WolfCrier Risk Comparison

#### Overview
This script compares two JSON files containing API response data (yesterday's and today's) and highlights differences in an HTML table. Rows with new data are highlighted in green, while rows with missing data are in red. Additionally, the table is sorted by the comparison type (e.g., new data appears at the top) and by specific tags.

#### How to Run the Script

1. **Input Files**: 
   - Ensure that you have two JSON files: one for yesterday's data and one for today's data.
   - The script expects these JSON files to be formatted in a specific way, as described in earlier sections (formatted API output).

2. **Run the Script**:
   - Simply run the Python script. It will:
     - Load both JSON files.
     - Compare the data.
     - Generate an HTML file showing the differences with color highlights.

3. **Output**:
   - The output will be an HTML file that shows the differences between yesterday's and today's API response data.
   - The HTML file will include a title and a table with several columns.

#### Script Structure

- **Comparison Logic**: The script compares the keys and values in the JSON files. It highlights:
  - Rows that are new (appear in today’s data but not in yesterday’s).
  - Rows that are missing (appear in yesterday’s data but not in today’s).
  - Rows that are unchanged.

- **Sorting**: The table is sorted by the presence of new or missing data (`right_only` for new, `left_only` for missing). Then it sorts by specific tag values and the `Service` column, which is part of the data structure.

- **Styling**: The table is styled with a black background and white text, with green and red highlights for new and missing rows respectively.

#### Adding a New Metadata Column

If you want to add additional columns to the table that contain metadata but are not involved in the sorting, follow these steps:

1. **Step 1: Modify DataFrame to Add the Column**
   - Before the table is output to HTML, you can add new metadata columns.
   - Example: Let’s say you want to add a column named `Source`.

   ```python
   comparison_df['Source'] = 'API1'  # Adding a column with the same value for all rows
   ```

   If your metadata comes from another list or another source, you can map that data to the new column. For example:

   ```python
   metadata_dict = {
       'Key1': 'API1',
       'Key2': 'API2',
       # Add more key-to-source mappings as needed
   }

   # Apply the metadata to the new column based on the 'Key' column
   comparison_df['Source'] = comparison_df['Key'].map(metadata_dict)
   ```

   This will create a `Source` column with metadata that is linked to the key.

2. **Step 2: Ensure New Column Is Included in the HTML Output**
   - If you want the new metadata column to be included in the HTML output, make sure it is part of the DataFrame before you convert it to HTML. You don’t need to modify the sorting logic for metadata columns.

   ```python
   # Ensure new metadata columns are in the DataFrame before styling
   styled_df = comparison_df.style.apply(highlight_diff, axis=None)
   
   # Generate HTML
   html_output = styled_df.to_html()
   ```

3. **Step 3: View the HTML Output**
   - After you run the script, the new column will be visible in the HTML file along with the other columns. The added metadata will be displayed, but it won’t affect the sorting.

#### Example of Adding Multiple Metadata Columns

If you need to add more than one column, the process is the same. Just repeat the steps for each column:

```python
# Add a column for 'Source'
comparison_df['Source'] = comparison_df['Key'].map(metadata_dict)

# Add a column for 'Region'
comparison_df['Region'] = comparison_df['Key'].map(region_dict)
```

This approach can be used for any number of metadata columns.

#### Summary

- You can add metadata columns to the table by simply modifying the DataFrame.
- Metadata columns won't affect the sorting logic, so they can be added safely after all comparisons and sorting are done.
- The script will generate a well-formatted HTML file, complete with any metadata columns you add.

This documentation should help you extend the script and make use of metadata columns effectively!