import streamlit as st
import requests
import pprint  # For debugging, can be removed from final UI output
from tenacity import retry, stop_after_attempt, wait_exponential  # Added for retry mechanism
import logging
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

if st.__version__ < "1.0.0":
    st.error("Please upgrade Streamlit to version 1.0.0 or higher.")

# --- Xandr API Configuration ---
XANDR_BASE_URL = "https://api.appnexus.com"

# --- Helper Functions (Refactored from your script) ---

def get_cities_for_country(token: str, country_name: str, city_name: str = None) -> list[dict] | None:
    """Fetches city IDs for a given country and optionally filters by city name."""
    url = f"{XANDR_BASE_URL}/city"
    params = {'name': country_name}
    headers = {"Authorization": token}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        json_response = response.json()

        if 'response' not in json_response or 'cities' not in json_response['response']:
            st.error(f"Unexpected API response structure when fetching cities for {country_name}.")
            st.json(json_response)  # Show the problematic response
            return None

        if not isinstance(json_response.get('response', {}).get('cities', []), list):
            st.error("Unexpected API response structure.")
            return None

        cities_data = json_response['response']['cities']
        filtered_data = []
        for city in cities_data:
            # Filter by country name
            if city.get('country_name', '').lower() == country_name.lower():
                # Optionally filter by city name
                if city_name and city.get('name', '').lower() != city_name.lower():
                    continue
                filtered_data.append({"id": city['id']})

        if not filtered_data:
            st.warning(f"No cities found for country: {country_name} and city: {city_name}.")
            return None
        return filtered_data
    except requests.exceptions.RequestException as e:
        st.error(f"API Error fetching cities: {e}")
        logging.error(f"API Error fetching cities: {e}")
        if hasattr(e, 'response') and e.response is not None:
            st.json(e.response.json())
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while fetching cities: {e}")
        return None

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def update_line_item_profile_geo(token, profile_id, city_targets):
    """Updates the geo targeting for a given profile ID."""
    url = f"{XANDR_BASE_URL}/profile?id={profile_id}"  # ID in query param for PUT on profile
    headers = {"Authorization": token}
    data = {
        "profile": {
            "id": profile_id,
            "city_targets": city_targets,
            "city_action": "include"  # This will replace existing city targets
        }
    }
    try:
        response = requests.put(url, headers=headers, json=data)
        response.raise_for_status()
        json_response = response.json()

        # Check if the response contains the expected keys
        if 'response' not in json_response or 'status' not in json_response['response']:
            st.error(f"Unexpected API response structure while updating profile ID {profile_id}.")
            st.json(json_response)  # Show the problematic response
            return None

        return json_response
    except requests.exceptions.RequestException as e:
        st.error(f"API Error updating profile ID {profile_id}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            st.json(e.response.json())
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred while updating profile: {e}")
        return None

def get_line_item_ids_from_io(token: str, insertion_order_id: int) -> list[int] | None:
    """Fetches line item IDs for a given insertion order ID."""
    url = f"{XANDR_BASE_URL}/line-items?insertion_order_id={insertion_order_id}"
    headers = {"Authorization": token}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_response = response.json()
        return [item['id'] for item in json_response.get('response', {}).get('line_items', [])]
    except Exception as e:
        logging.error(f"Error fetching line item IDs: {e}")
        return None

def get_profile_id_for_line_item(token: str, line_item_id: int) -> int | None:
    """Fetches the profile ID for a given line item ID."""
    # Placeholder implementation
    return 54321  # Replace with actual API call logic

def authenticate(username: str, password: str) -> str | None:
    """Authenticates the user and retrieves the API token."""
    credentials = {"auth": {"username": username, "password": password}}
    try:
        response = requests.post(f"{XANDR_BASE_URL}/auth", json=credentials)
        response.raise_for_status()
        json_response = response.json()

        if 'response' in json_response and 'token' in json_response['response']:
            return json_response['response']['token']
        else:
            st.error("Authentication failed. Please check your credentials.")
            st.json(json_response)  # Show the problematic response for debugging
            return None
    except requests.exceptions.RequestException as e:
        st.error(f"Error during authentication: {e}")
        logging.error("Error during authentication: Redacted sensitive data.")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred during authentication: {e}")
        logging.error(f"Unexpected error during authentication: {e}")
        return None

# --- Streamlit UI ---
st.set_page_config(layout="wide")
st.title("Xandr Tools: Geo Targeting & Conversion Pixels")

# Tabs for different tools
tab1, tab2 = st.tabs(["Geo Targeting Updater", "Conversion Pixel Updater"])

# --- Tab 1: Geo Targeting Updater ---
with tab1:
    st.header("Geo Targeting Updater")
    st.sidebar.header("Geo Targeting Inputs")
    country_name_input = st.sidebar.text_input("Country Name", placeholder="e.g., Sweden, Germany, United States")
    city_name_input = st.sidebar.text_input("City Name (Optional)", placeholder="e.g., Stockholm")
    insertion_order_id_input = st.sidebar.text_input(
        "Insertion Order ID (Optional)", 
        placeholder="Enter a valid Insertion Order ID",
        help="Provide the Insertion Order ID to update all line items within it."
    )
    line_item_ids_input = st.sidebar.text_area(
        "Line Item IDs (Optional)", 
        placeholder="Enter line item IDs separated by commas (e.g., 12345, 67890, 11223)",
        help="Provide the line item IDs you want to update. Leave blank to skip line item updates."
    )

    if st.sidebar.button("Update Geo Targeting"):
        # Check if the API token is available
        api_token = st.session_state.get("api_token")
        if not api_token:
            st.sidebar.error("You must authenticate to generate an API token.")
            st.stop()

        # Validate inputs
        if not country_name_input:
            st.sidebar.error("Country Name is required.")
            st.sidebar.info("Please enter a valid country name to proceed.")
            st.stop()

        # Parse and validate line item IDs (if provided)
        line_item_ids = []
        if line_item_ids_input.strip():
            try:
                line_item_ids = [int(li.strip()) for li in line_item_ids_input.split(",") if li.strip().isdigit()]
                if not line_item_ids:
                    raise ValueError("No valid line item IDs provided.")
            except ValueError as e:
                st.sidebar.error(f"Invalid Line Item IDs: {e}")
                st.stop()

        # Fetch line item IDs from the insertion order (if provided)
        if insertion_order_id_input.strip():
            try:
                insertion_order_id = int(insertion_order_id_input.strip())
                io_line_item_ids = get_line_item_ids_from_io(api_token, insertion_order_id)
                if io_line_item_ids:
                    line_item_ids = list(set(line_item_ids + io_line_item_ids))  # Combine and remove duplicates
                else:
                    st.sidebar.warning(f"No line items found for Insertion Order ID {insertion_order_id}.")
            except ValueError:
                st.sidebar.error("Invalid Insertion Order ID. It must be a number.")
                st.stop()

        if not line_item_ids:
            st.sidebar.error("No line item IDs provided or found. Please provide valid Line Item IDs or an Insertion Order ID.")
            st.stop()

        st.header("Processing Log")
        status_placeholder = st.empty()

        # 1. Get City IDs for the country
        status_placeholder.info(f"Fetching city IDs for {country_name_input}...")
        logging.info(f"Fetching city IDs for {country_name_input}")
        city_targets_data = get_cities_for_country(api_token, country_name_input, city_name_input)

        if not city_targets_data:
            status_placeholder.error(f"Could not retrieve city data for {country_name_input}. Halting process.")
            st.stop()

        st.subheader(f"Cities found for {country_name_input}:")
        st.write(f"{len(city_targets_data)} cities identified.")
        with st.expander("Show City IDs (first 10)"):
            st.json([city['id'] for city in city_targets_data[:10]])  # Show only IDs for brevity

        # 2. Process Line Items
        total_lis = len(line_item_ids)
        success_count = 0
        failure_count = 0

        progress_bar = st.progress(0)
        results_container = st.container()  # To append results dynamically

        def process_line_item(li_id):
            profile_id = get_profile_id_for_line_item(api_token, li_id)
            if profile_id:
                return update_line_item_profile_geo(api_token, profile_id, city_targets_data)
            return None

        with ThreadPoolExecutor() as executor:
            results = list(executor.map(process_line_item, line_item_ids))

        for i, result in enumerate(results):
            li_id = line_item_ids[i]
            if result and result.get('response', {}).get('status') == 'OK':
                results_container.success(f"Line Item {li_id}: Geo targeting updated successfully.")
                success_count += 1
            else:
                results_container.error(f"Line Item {li_id}: Failed to update geo targeting.")
                if result:  # Show response if available
                    with results_container.expander(f"Details for Line Item {li_id} update failure"):
                        st.json(result)
                failure_count += 1

            if i % 10 == 0 or i == total_lis - 1:
                progress_bar.progress((i + 1) / total_lis)

        # Final Summary
        status_placeholder.empty()  # Clear the "processing" message
        st.header("Processing Complete")
        st.success(f"Successfully updated {success_count} line item(s).")
        if failure_count > 0:
            st.error(f"Failed to update {failure_count} line item(s). Check logs above for details.")
        else:
            st.info("All targeted line items processed.")

# --- Tab 2: Conversion Pixel Updater ---
with tab2:
    st.header("Conversion Pixel Updater")
    st.sidebar.header("Conversion Pixel Inputs")
    insertion_order_id_input = st.sidebar.text_input(
        "Insertion Order ID (Optional)", 
        placeholder="Enter a valid Insertion Order ID",
        help="Provide the Insertion Order ID to update all line items with the new conversion pixel."
    )
    line_item_ids_input = st.sidebar.text_area(
        "Line Item IDs (Optional)", 
        placeholder="Enter line item IDs separated by commas (e.g., 12345, 67890, 11223)",
        help="Provide the line item IDs you want to update. Leave blank to update all line items in the insertion order."
    )
    new_pixel_id_input = st.sidebar.text_input(
        "New Conversion Pixel ID", 
        placeholder="Enter the new conversion pixel ID",
        help="Provide the ID of the new conversion pixel to apply."
    )

    if st.sidebar.button("Update Conversion Pixels"):
        # Check if the API token is available
        api_token = st.session_state.get("api_token")
        if not api_token:
            st.sidebar.error("You must authenticate to generate an API token.")
            st.stop()

        # Validate inputs
        if not new_pixel_id_input.strip():
            st.sidebar.error("New Conversion Pixel ID is required.")
            st.stop()

        try:
            new_pixel_id = int(new_pixel_id_input.strip())
        except ValueError:
            st.sidebar.error("Conversion Pixel ID must be a valid number.")
            st.stop()

        # Parse and validate line item IDs (if provided)
        line_item_ids = []
        if line_item_ids_input.strip():
            try:
                line_item_ids = [int(li.strip()) for li in line_item_ids_input.split(",") if li.strip().isdigit()]
                if not line_item_ids:
                    raise ValueError("No valid line item IDs provided.")
            except ValueError as e:
                st.sidebar.error(f"Invalid Line Item IDs: {e}")
                st.stop()

        # Fetch line item IDs from the insertion order (if provided)
        if insertion_order_id_input.strip():
            try:
                insertion_order_id = int(insertion_order_id_input.strip())
                io_line_item_ids = get_line_item_ids_from_io(api_token, insertion_order_id)
                if io_line_item_ids:
                    line_item_ids = list(set(line_item_ids + io_line_item_ids))  # Combine and remove duplicates
                else:
                    st.sidebar.warning(f"No line items found for Insertion Order ID {insertion_order_id}.")
            except ValueError:
                st.sidebar.error("Invalid Insertion Order ID. It must be a number.")
                st.stop()

        if not line_item_ids:
            st.sidebar.error("No line item IDs provided or found. Please provide valid Line Item IDs or an Insertion Order ID.")
            st.stop()

        # Fetch advertiser ID (if insertion order is provided)
        advertiser_id = None
        if insertion_order_id_input.strip():
            response = requests.get(f"{XANDR_BASE_URL}/insertion-order?id={insertion_order_id}", headers={"Authorization": api_token})
            response.raise_for_status()
            json_response = response.json()
            advertiser_id = json_response['response']['insertion-order']['advertiser_id']

        st.header("Processing Conversion Pixel Updates")
        progress_bar = st.progress(0)
        success_count = 0
        failure_count = 0

        for i, line_item_id in enumerate(line_item_ids):
            url = f"{XANDR_BASE_URL}/line-item?id={line_item_id}"
            if advertiser_id:
                url += f"&advertiser_id={advertiser_id}"
            data = {
                "line-item": {
                    "id": line_item_id,
                    "pixels": [{"id": new_pixel_id, "state": "active"}]
                }
            }

            try:
                response = requests.put(url, headers={"Authorization": api_token}, json=data)
                response.raise_for_status()
                json_response = response.json()
                if json_response.get('response', {}).get('status') == 'OK':
                    st.success(f"Line Item {line_item_id}: Conversion pixel updated successfully.")
                    success_count += 1
                else:
                    st.error(f"Line Item {line_item_id}: Failed to update conversion pixel.")
                    failure_count += 1
            except Exception as e:
                st.error(f"Line Item {line_item_id}: Error updating conversion pixel: {e}")
                failure_count += 1

            progress_bar.progress((i + 1) / len(line_item_ids))

        # Final Summary
        st.header("Processing Complete")
        st.success(f"Successfully updated {success_count} line item(s).")
        if failure_count > 0:
            st.error(f"Failed to update {failure_count} line item(s). Check logs above for details.")