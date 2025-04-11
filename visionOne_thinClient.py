import requests #third-party module
import json
import re

class visionOne:

    '''
    Author: Paolo Campus, Deloitte
    Code written following documentation here: https://automation.trendmicro.com/xdr/api-v3
    '''

    #timeout for http calls
    timeout = 60

       

    def __init__(self, baseURL, token, proxy):    
        """
            Constructor Method
                Input:
                    baseURL : str
                            URL to TrendMicro VisionOne platform
                    token : str
                            Authentication parameter        
        """
        self.baseUrl = baseURL 
        self.token = token
        self.proxy = proxy
               

        #Other parameters used during POST request 
        self.query_params = {}
        self.headers = {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json;charset=utf-8'
        }

    #send POST request 
    def post_request(self, url_path, headers, body):
        
        try:
            
            r = requests.post(self.baseUrl + url_path, params=self.query_params, headers=self.headers, json=body, timeout=visionOne.timeout, proxies=self.proxy)
        
        except Exception as e:
            r = "Error during Post request: " + str(e)
        
        return r
    
    #parse the output that comes from POST
    def parse_output(self, response):

        exit_code = 0 #set 0 as default
               
        try:
            exit_code = response.status_code
            if 'application/json' in response.headers.get('Content-Type', '') and len(response.content):
                parsed_output = response.json()
            else:
                parsed_output = response.text
        
        except Exception as e:
            parsed_output = "Error parsing Post response: " + str(e) + "\nPost response was: '" + str(response) + "'"
            exit_code = -1
        
        return [exit_code, parsed_output]

    
    #function used to make search either by ip or endpoint in "getinfoFromIP"
    def get_type(self, analyst_input):    
        ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')        
        # Check if the input matches the IPv4 pattern
        if ipv4_pattern.match(analyst_input):
            # Split the input by dots and check each segment is between 0 and 255
            if all(0 <= int(segment) <= 255 for segment in analyst_input.split('.')):
                analyst_input_type = "ip"
            else:
                analyst_input_type = "endpointName"
        else:
            analyst_input_type = "endpointName"

        return analyst_input_type

    #function used to format the response from 'get_infoFromIP'
    def __format_infoFromIP(self, response, case_param):
        formatted_output = []

        if (case_param == "info"):  

            for idx, item in enumerate(response.get("items", []), start=1):
                agent_guid = item.get("agentGuid", "N/A")
                login_account_values = item.get("loginAccount", {}).get("value", "")
                login_account = login_account_values[0].replace("\\", "/") if login_account_values else "N/A"
                endpoint_name = item.get("endpointName", {}).get("value", "")
                os_info = item.get("osDescription", "")
                policy_name = item.get("policyName", "")
                protection_manager = item.get("protectionManager", "")
                ip_visionone = item.get("ip", {}).get("value", "")
                
                entry = (f"Result {idx}\n"
                        f"\t- AgentGuid: {agent_guid}\n"
                        f"\t- Login Account: {login_account}\n"
                        f"\t- Endpoint Name: {endpoint_name}\n"
                        f"\t- IP: {ip_visionone}\n"
                        f"\t- OS info: {os_info}\n"
                        f"\t- Policy name: {policy_name}\n"
                        f"\t- Protection Manager: {protection_manager}\n"
                        f"\n"
                        f"\t- Get more detail for this result --> https://threat-connect-app.srv.sogei.it/api/playbook/visionOne_soar?action=get_detailedInfoForEndpoint&value={agent_guid}\n"     
                        f"\n"    
                        )
                formatted_output.append(entry)          

            return "\n".join(formatted_output)
        
        if (case_param == "links"):
            for idx, item in enumerate(response.get("items", []), start=1):
                agent_guid = item.get("agentGuid", "N/A")
                login_account_values = item.get("loginAccount", {}).get("value", "")
                login_account = login_account_values[0].replace("\\", "/") if login_account_values else "N/A"
                endpoint_name = item.get("endpointName", {}).get("value", "")
                ip_visionone = item.get("ip", {}).get("value", "")
                
                entry = (f"Risultato {idx}\n"
                        f"\t- IP: {ip_visionone}\n"
                        f"\t- AgentGuid: {agent_guid}\n"
                        f"\t- Login Account: {login_account}\n"
                        f"\t- Nome Host: {endpoint_name}\n"   
                        f"\n"
                        f"\t- Isola host\n\tlink --> https://threat-connect-app.srv.sogei.it/api/playbook/visionOne_soar?action=isolate&value={agent_guid}\n"
                        f"\t- Ripristina host\n\tlink --> https://threat-connect-app.srv.sogei.it/api/playbook/visionOne_soar?action=restore&value={agent_guid}\n"                  
                        
                        )
                formatted_output.append(entry)          

            return "\n".join(formatted_output)

        
        
    
    #Methods available

    def get_detailedInfoForEndpoint(self, agentID):      
        '''
        API in TMV1 doc: Endpoint Security -> Get endpoint details
        '''

        exit_code = 0  #set 0 as default

        url_path = '/v3.0/endpointSecurity/endpoints/'+ agentID
        
        query_params = {}
        headers = {
                    'Authorization': 'Bearer ' + self.token,
                }

        try:
            r = requests.get(self.baseUrl + url_path, params=query_params, headers=headers, timeout=visionOne.timeout, proxies=self.proxy)
            result = self.parse_output(r)
            
            if (result[0] == 200):
                
                #handle empty response
                if isinstance(result[1], dict):
                    info = result[1]
                    exit_code = result[0]
                else:
                    exit_code = 404
                    result[1]["items"].append("Endpoint details not found on TrendMicro Vision One")
                    info = result[1]
                
            else:
                exit_code = result[0]
                info = result[1]
        
        except Exception as e:
            info = "Error getting info for endpoint with agentid " + agentID + "\n" + str(e) + "\n" + str(result)
            exit_code = -1
             
               
        return [exit_code, info]

    #get infoFromIP  
    def get_infoFromIP(self, ip):        
        '''
        API in TMV1 doc: Search -> Get detailed endpoint list
        '''

        exit_code = 0  #set 0 as default

        url_path = '/v3.0/eiqs/endpoints'
        get_type = self.get_type(ip)       
        
        query_params = {
                    'top': 200
                    }
        headers = {
                    'Authorization': 'Bearer ' + self.token,
                    'TMV1-Query': "{} eq '{}'".format(get_type, ip)
                }

        try:
            r = requests.get(self.baseUrl + url_path, params=query_params, headers=headers, timeout=visionOne.timeout, proxies=self.proxy)
            result = self.parse_output(r)
            
            if (result[0] == 200):
                
                #handle empty response
                if (len(result[1].get("items")) > 0):
                    info = self.__format_infoFromIP(result[1], "info")
                    exit_code = result[0]
                else:
                    exit_code = 404
                    result[1]["items"].append("Endpoint not found on TrendMicro Vision One")
                    info = result[1]
                
            else:
                exit_code = result[0]
                info = result[1]
        
        except Exception as e:
            info = "Error getting info for ip " + ip + "\n" + str(e) + "\n" + str(result)
            exit_code = -1
             
               
        return [exit_code, info]

    
    #get linksFromIP  
    def get_linksFromIP(self, ip):        
        '''
        API in TMV1 doc: Search -> Get detailed endpoint list
        '''

        exit_code = 0  #set 0 as default

        url_path = '/v3.0/eiqs/endpoints'
        get_type = self.get_type(ip)       
        
        query_params = {
                    'top': 200 
                    }
        headers = {
                    'Authorization': 'Bearer ' + self.token,
                    'TMV1-Query': "{} eq '{}'".format(get_type, ip)
                }

        try:
            r = requests.get(self.baseUrl + url_path, params=query_params, headers=headers, timeout=visionOne.timeout, proxies=self.proxy)
            result = self.parse_output(r)
            
            if (result[0] == 200):
                
                #handle empty response
                if (len(result[1].get("items")) > 0):
                    info = self.__format_infoFromIP(result[1], "links")
                    exit_code = result[0]
                else:
                    exit_code = 404
                    result[1]["items"].append("Endpoint not found on TrendMicro Vision One")
                    info = result[1]
                
            else:
                exit_code = result[0]
                info = result[1]
        
        except Exception as e:
            info = "Error getting info for ip " + ip + "\n" + str(e) + "\n" + str(result)
            exit_code = -1
             
               
        return [exit_code, info]
    
    #isolate
    def isolate(self, endpoint_agentguid):
        '''
        API in TMV1 doc: Endpoints -> Isolate endpoints
        '''
        url_path = '/v3.0/response/endpoints/isolate'

        body = [ {
                    'description': 'Isolate Endpoint',
                    'agentGuid': endpoint_agentguid
                }
        ]

        r = self.post_request(url_path, self.headers, body)
        result = self.parse_output(r)        
        return result

    
    #restore
    def restore(self, endpoint_agentguid):        
        '''
        API in TMV1 doc: Endpoints -> Restore endpoint connection
        '''
        url_path = '/v3.0/response/endpoints/restore'

        body = [ {
                    'description': 'Restore Endpoint',
                    'agentGuid': endpoint_agentguid
                }
        ]
                
        r = self.post_request(url_path, self.headers, body)
        result = self.parse_output(r)        
        return result

    
    #Workbench change status
    
    def get_workbench_etag(self, workbenchID):        
        '''
        API in TMV1 doc: Workbench -> Get alert details        
        
        Method needed because to change the WB status we have to pass the ETag value
        that we can get only from the headers of the 'Get alert detail' response
        '''
        output_param = []
        url_path = '/v3.0/workbench/alerts/{id}'
        url_path = url_path.format(**{'id': workbenchID})       

        query_params = {}
        headers = {
            'Authorization': 'Bearer ' + self.token,
        }
        
        try:
            r = requests.get(self.baseUrl + url_path, params=query_params, headers=headers, timeout=visionOne.timeout, proxies=self.proxy)
            
            etag = r.headers.get("ETag", "W/'Unknown'")[2:] #we need only the substring
            
            output_response_parsed = self.parse_output(r)
            WB_link = output_response_parsed[1].get("workbenchLink","https://portal.eu.xdr.trendmicro.com/index.html#/workbench/alerts/" + workbenchID)
                    
        except Exception as e:
            etag = "Error getting ETag for workbench {}: headers -> {}".format(workbenchID, r.headers)
            WB_link = "https://portal.eu.xdr.trendmicro.com/index.html#/workbench/alerts/" + workbenchID


        output_param.append(etag)
        output_param.append(WB_link)

        return output_param

    def workbench_change_status(self, workbenchID, status):        
        '''
        API in TMV1 doc: Workbench -> Modify alert status        
        '''
        
        url_path = '/v3.0/workbench/alerts/{id}'
        url_path = url_path.format(**{'id': workbenchID})

        buff = self.get_workbench_etag(workbenchID)
        etag = buff[0]
        wb_link = buff[1]
           

        query_params = {}
        headers = {
            'Authorization': 'Bearer ' + self.token,
            'Content-Type': 'application/json;charset=utf-8',
            'If-Match': etag
        }
        body = {
            'status': status,
            'investigationResult': 'Other Findings'
        }

        try:
            r = requests.patch(self.baseUrl + url_path, params=query_params, headers=headers, json=body, timeout=visionOne.timeout, proxies=self.proxy)
            result = self.parse_output(r)
            
            if (result[0] == 204):                
                #handle correct but empty response
                info = "Vision One Workbench {} status changed to {}\n\nWorkbench link: {}".format(workbenchID, status, wb_link)
                exit_code = result[0]
                
            else:
                exit_code = result[0]
                info = result[1] + "\n\nWorkbench link: {}".format(wb_link)
        
        except Exception as e:
            info = "Error updating workbench {} status to {}\n\nWorkbench link: {}".format(workbenchID, status, wb_link)
            exit_code = -1            
               
        return [exit_code, info]


    def inProgess_workbench(self, workbenchID):
        return self.workbench_change_status(workbenchID, "In Progress")

    def close_workbench(self, workbenchID):
        return self.workbench_change_status(workbenchID, "Closed")
    
