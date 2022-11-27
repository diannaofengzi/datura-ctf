import os
import sys
import re

topics = ["Scanning", "Services and Ports", "Reverse Shell", "Privilege Escalation", "Binary Exploitation", "Classic Exploits", "Reverse Engineering", "Forensics",  "Cryptography", "Steganography", "PDF Files", "ZIP Files", "Hashes", "OSINT", "Network", "Jail Break", "Android", "Esoteric Languages", "Data Science", "Signal processing", "Chemistry", "Other CheatSheets"]
output_markdown_file = "./README.md"

# Parse the makrdown content and update the links
def updateLinks(content, topic_path):

    # Get potential links to other resources in the content
    links = re.findall(r"\[([^\]]+)\]\(([^\)]+)\)", content)

    # Add src="" links
    links += re.findall(r"(src)=\"([^\"]+)\"", content)

    # For each link, update the link if the link is a local link
    for link in links:

        # Link to a Datura md file
        if link[1].endswith("README.md") and not "http" in link[1]:
            # If the link have at least a directory, keep only the last directory
            if "/" in link[1]:
                dir_name = link[1].split("/")[-2]
                content = content.replace(link[1], "#" + dir_name.lower().replace(" ", "-"))


        # Link inside a directory
        if link[1].startswith("./"):
            topic_path = topic_path.replace(" ", "%20")
            content = content.replace(link[1], link[1].replace("./", topic_path + "/"))

        # Link outside a directory : Replace the ../ by the topic name minus the last directory if exists
        if link[1].startswith("../"):
                i = 0
                while not i > len(topic_path) and topic_path[-i] != "/":
                    i += 1
                dotdot_path = topic_path[:-i] + "/"
                dotdot_path = dotdot_path.replace(" ", "%20")
                content = content.replace(link[1], link[1].replace("../", dotdot_path))
            





    return content



def addTopic(topic):

    files = os.listdir(topic)

    if "README.md" in files:
        file = "README.md"
        with open(topic + "/" + file, "r", encoding='utf-8') as local_readme_fd:
            content = local_readme_fd.read()
        content = updateLinks(content, topic)
        with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
            output_fd.write(content)

    for file in os.listdir(topic):

            # If the file is a directory, add the content of the README.md file
            if os.path.isdir(topic + "/" + file):
                if not file.startswith(".") and not file.startswith("_") and not file == "Tools":
                    with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
                        output_fd.write("\n\n## " + file + "\n\n")
                    addTopic(topic + "/" + file)

def main():

    # Reset the README.md file
    with open(output_markdown_file, "w", encoding='utf-8') as output_fd:
        output_fd.write("")

    # Introduction
    addTopic("Introduction")

    # Add auto generated warning
    with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
        output_fd.write("\nThis file is auto generated using [build.py](build.py). To update it, update the README.md files in the subdirectories and run the build.py script.\n")

    # Table of Contents
    with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
        output_fd.write("\n# Table of Contents\n")
    for topic in topics:
        with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
            output_fd.write("* [" + topic + "](#" + topic.lower().replace(" ", "-") + ")\n")

    # For each topic, add the topic name and the links to the README.md file
    for topic in topics:

        with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
            output_fd.write("\n<br><br>\n\n# " + topic + "\n\n")
        addTopic(topic)

if __name__ == "__main__":
    main()