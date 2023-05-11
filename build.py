import os
import sys
import re

# Parameters
topics = ["Scanning", "Services and Ports", "Reverse Shell", "Reverse Engineering", "Binary Exploitation", "Privilege Escalation", "Classic Exploits", "Forensics", "Cryptography", "Steganography", "PDF Files", "ZIP Files", "Hashes", "OSINT", "Network", "Jail Break", "Android", "Web", "Miscellaneous", "Other Resources"]
output_markdown_file = "./README.md"

special_words = {":heart:": "<span style=\"color:red\">❤️</span>"}

# Parse the makrdown content and update the links
def update_links(content, topic_path):

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
                content = content.replace(link[1], "#" + dir_name.lower().replace(" ", "-").replace("%20", "-"))


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

def replace_special_words(content, special_words):
    """Replace special words with their corresponding code"""
    for word in special_words:
        # Replace all occurences of the word
        regex = re.compile(word)
        content = re.sub(regex, special_words[word], content)
    return content




def add_topic(topic, depth=0):

    # List directories in the current directory
    directories = [d for d in os.listdir(topic) if os.path.isdir(os.path.join(topic, d))]

    # Add links to the directories in a rectangle
    with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
        for directory in directories:
            if not directory.startswith(".") and not directory.startswith("_") and not directory == "Tools":
                output_fd.write("⇨ [" + directory + "](#" + directory.lower().replace(" ", "-") + ")<br>")
        output_fd.write("\n\n")
        
    files = os.listdir(topic)

    if "README.md" in files:
        file = "README.md"
        with open(topic + "/" + file, "r", encoding='utf-8') as local_readme_fd:
            content = local_readme_fd.read()
        content = update_links(content, topic)
        content = replace_special_words(content, special_words)
        with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
            output_fd.write(content)

    for file in os.listdir(topic):

            # If the file is a directory, add the content of the README.md file
            if os.path.isdir(topic + "/" + file):
                if not file.startswith(".") and not file.startswith("_") and not file == "Tools":
                    with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
                        output_fd.write("\n\n##" + "#" * depth + " " + file + "\n\n")
                    add_topic(topic + "/" + file, depth=depth+1)
                    with open(output_markdown_file, "a", encoding='utf-8') as output_fd:
                        output_fd.write("\n\n")

def main():

    # Reset the README.md file
    with open(output_markdown_file, "w", encoding='utf-8') as output_fd:
        output_fd.write("")

    # Introduction
    add_topic("Introduction")

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
        add_topic(topic)

if __name__ == "__main__":
    main()