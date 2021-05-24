<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

<!-- PROJECT LOGO -->
<br />

<!-- ABOUT THE PROJECT -->

## About The Project



<img src="resource/wd.png" alt="Logo">

This project based on [taviso](https://github.com/taviso)/**[loadlibrary](https://github.com/taviso/loadlibrary)**

This demo is a simple PoC of Customizable and Portable Windows Defender

You can make the your own customized functions by hooking functions of Windows Defender.

So I offer the mpengine.dll which has the MS Debug Symbol and 2 Simple PoC (ThreatTraceCallback, ScanInfoHook)



<!-- GETTING STARTED -->
## Getting Started

<img src="resource/poc.gif" alt="Logo">

```sh
mploader.exe -f "target_file"
```



### Prerequisites

* MPEngine and it's AV Container
  ```sh
  https://drive.google.com/drive/folders/1ESzYr4aD7kyrdwrwzVYhdR3A_DQA0H_1?usp=sharing
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/orca-eaa5a/mploader.git
   ```
   
2. Locate the MPEngine and AV Container at "engine" directory

   

<!-- USAGE EXAMPLES -->

## Usage

* Options

   ```sh
   -f file_name	: Target file to scan
   -r (related)	: Get related threats of target file which was detected
   -l (log)		: Log API call
   -l reg			: Log API call with registry and stack
   -u (unpack)		: Enable unpacking method
   -t (trace)		: Get the file offset of threats detected
   ```

<!-- LICENSE -->

## License

Distributed under the MIT License.


