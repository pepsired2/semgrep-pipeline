import json
import requests
import logging
import os
import re
import pandas as pd

def get_data(deployment_id, repo):
    """
    Fetches the secrets data from the Semgrep API for the given deployment and repository.

    Args:
        deployment_id (str): The deployment ID for which to fetch the secrets.
        repo (str): The repository name for which to fetch the secrets.

    Returns:
        List[Dict]: A list of findings from the Semgrep API.
    """

    try:
        SEMGREP_API_WEB_TOKEN = os.environ["SEMGREP_API_WEB_TOKEN"]
    except KeyError:
        raise

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {SEMGREP_API_WEB_TOKEN}"
    }

    params = {"repo": repo}
    base_url = f'https://semgrep.dev/api/v1/deployments/{deployment_id}/secrets'
    data = []

    with requests.Session() as session:
        try:
            # Initial request
            response = session.get(base_url, params=params, headers=headers)
            response.raise_for_status()
            result = response.json()
            cursor = result.get('cursor')
            data.extend(result.get('findings', []))

            # Subsequent requests if cursor exists
            while cursor:
                params['cursor'] = cursor
                response = session.get(base_url, params=params, headers=headers)
                response.raise_for_status()
                result = response.json()
                cursor = result.get('cursor')
                data.extend(result.get('findings', []))

        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
            raise

        except ValueError as e:
            logging.error(f"Error parsing JSON response: {e}")
            raise

    return data

def count_severity_and_state(data):
    counts = {
        'critical': {'open': 0, 'ignored': 0, 'fixed': 0, 'removed': 0, 'unknown': 0},
        'high':  {'open': 0, 'ignored': 0, 'fixed': 0, 'removed': 0, 'unknown': 0},
        'medium':  {'open': 0, 'ignored': 0, 'fixed': 0, 'removed': 0, 'unknown': 0},
        'low':  {'open': 0, 'ignored': 0, 'fixed': 0, 'removed': 0, 'unknown': 0}
    }

    for item in data:
        severity = item.get('severity').lower()
        if 'critical' in severity:
            severity = 'critical'
        elif 'high' in severity:
            severity = 'high'
        elif 'medium' in severity:
            severity = 'medium'
        elif 'low' in severity:
            severity = 'low'

        state = item.get('state').lower()
        if 'open' in state:
            state = 'open'
        elif 'ignored' in state:
            state = 'ignored'
        elif 'fixed' in state:
            state = 'fixed'
        elif 'removed' in state:
            state = 'removed'
        elif 'unknown' in state:
            state = 'unknown'

        if severity in counts and state in counts[severity]:
            counts[severity][state] += 1

    return counts

def generate_reports(data, json_file_path, repo, EPOCH_TIME):
    with open(json_file_path, "w") as file:
        json.dump(data, file)
        logging.info("Secret findings for requested project/repo: " + repo + "written to: " + json_file_path)

    # count sevrity data

    severity_and_state_counts = count_severity_and_state(data)
    logging.debug(f"severity_and_state_counts in repo: {repo} - {severity_and_state_counts}")
    output_folder = os.path.join(os.getcwd(), "reports", EPOCH_TIME)  # Define the output path
    output_name = re.sub(r"[^\w\s]", "_", repo)
    logging.debug ("output_name: " + output_name)

    csv_file = output_name + "-" + "secrets-" + EPOCH_TIME + ".csv"
    csv_file_path = os.path.join(output_folder, csv_file)
    xlsx_file = output_name + "-" + "secrets-" + EPOCH_TIME + ".xlsx"
    xlsx_file_path = os.path.join(output_folder, xlsx_file)
    html_file = output_name + "-" + "secrets-" + EPOCH_TIME +  ".html"
    html_file_path = os.path.join(output_folder, html_file)
    pdf_file = output_name + "-" + "secrets-" + EPOCH_TIME +  ".pdf"
    pdf_file_path = os.path.join(output_folder, pdf_file)

    logging.info(f"file names: {output_name}, {json_file_path},{csv_file_path}, {xlsx_file_path},{html_file_path}, {pdf_file_path}")

    json_to_csv_pandas(json_file_path, csv_file_path)
    logging.info (f"completed conversion process for repo: {repo}")

def json_to_csv_pandas(json_file, csv_file):

    df = json_to_df(json_file)
    # Write the DataFrame to CSV
    df.to_csv(csv_file, index=False)

    logging.info("Findings converted from JSON file : " + json_file + " to CSV File: " + csv_file)

def json_to_df(json_file):
    # Read the JSON file into a DataFrame
    df = pd.read_json(json_file)
    # filter out only specific columns
    df = df.loc[:, [ 'type', 'findingPath', 'repository', 'createdAt', 'updatedAt', 'status', 'severity', 'confidence',  'validationState']]
    logging.info("Findings converted to DF from JSON file : " + json_file)

    return df
