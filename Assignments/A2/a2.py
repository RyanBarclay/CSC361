#!/usr/bin/python3

# Not allowed to use any big boy libraries

    """Assignment 2 

    Requirements:
        Given a TCP Trace file, write a python file for parsing and processing the trace file. Note, we are only allowed specific packages that are on the UVic linux servers.
        The program should:
            * process the trace file and compute a summary of the information

        The summary should include for each TCP connection:
            * State of connection
            * Starting time
            * Ending time
            * Duration of each complete connnetion 
            * Number of packets sent in each direction, on each complete connection
            * Total number of packets 
            * Number of bytes sent in each direction, on each complete connection
            * Total bytes, excluding TCP and IP protocols 
        
        The summary should include for each cap file:
            * Number of reset TCP connections
            * Number of TCP connections still open when @ end of file
            * Number of complete TCP connections observed in file
                * Time durations
                    * Min
                    * Max
                    * Mean
                * RRT (Round Trip Times) values
                    * Min
                    * Max
                    * Mean
                * Number of packets in both directions sent
                    * Min
                    * Max
                    * Mean
                * Receive window sizes, both sides
                    * Min
                    * Max
                    * Mean
        
        For more info on the requirements look at the pdf contained in the A2 folder.

    Grading:
        25% - Total Number of connections 
        30% - Connections' details 
        20% - General Statistics 
        20% - Complete TCP connections 
        5%  - Readme.txt and coding style
    """

import socket
import sys
import re
import ssl
DEFAULT_HTTP_PORT = 80