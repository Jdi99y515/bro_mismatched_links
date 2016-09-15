module mismatched_links;

# This module creates notices when it detects a URL in an email_body
# where the link's displayed text contains a different domain
# than the actual link destination.
# 
# This is meant to help detect phishing attacks.


global DEBUG_MODE = T;

# Custom types used for processing
type notice_types: enum {
    LINK_TEXT_NOT_TARGET,
};

type match_result: enum {
    MATCH,
    MISMATCH,
    NA,
};

type EmailLink: record {
    raw_data: string;
    text: string;
    target: string;
    text_domain: string;
    target_domain: string;
    status: match_result;
};

type LinkVector: vector of EmailLink;

function print_debug(msg: string){
    if(DEBUG_MODE){
        print msg;
    }
}

# Functions for parsing

function examine_links(email_body: string) : LinkVector
{
    
    # Vector for storing results
    local result_links = LinkVector();

    #print "Before: " + email_body;
    # Strip all non-<a> tags
    email_body = gsub(email_body, /<([^\/aA]|[aA][^ ])([^<>]+)>/, "");
    email_body = gsub(email_body, /<\/([^aA]|[aA][^ ])([^<>]+)>/, "");
    #print "After1: " + email_body;
    
    local link_pattern = /<a [^<>]+>(([^<>]+)|([^<>]*<[^aA]([^<]+<\/[^<]*)))<\/a>/;
    local links = find_all(email_body, link_pattern);

    for (link in links){
        #print link;

        # Extract the URL's text:        
        local link_text_pattern = />[^<>]+<\/a>/;
        local link_text = "";
        
        link_text = match_pattern(link, link_text_pattern)$str;
        # Trim the angle brackets
        link_text = link_text[1:-4];

        # Extract the URL's destination:
        local link_target_pattern = /href=(\"|\')?([a-z\-]{3,5})(:\/\/[^\/?#"'\r\n><]*)([^?#"'\r\n><]*)([^[:blank:]\r\n"'><]*|\??[^"'\r\n><]*)/;
        
        local link_target = match_pattern(link, link_target_pattern)$str;
        # Strip the leading href= (and optional quote)
        link_target = link_target[5:];
        if (link_target[0] == "\"" || link_target[0] == "'"){
            link_target = link_target[1:];    
        }
        #print link_target;
        

        # Remove extra whitespace
        link_text = strip(link_text);
        link_target = strip(link_target);
            
        # We only examine the domain.
        # We therefore trim the protocol and path from each:
        
        local protocol_pattern = /https?:\/\//;
        if( protocol_pattern in link_text && protocol_pattern in link_target){

            local link_text_domain = sub(link_text, /^(http:\/\/|https:\/\/)/, "");
            
            print_debug("1." + link_text_domain);
            
            # Scraps anything after the first / (if there is a first /)
            link_text_domain = gsub(link_text_domain, /\/.*/, "");
            print_debug("2." + link_text_domain);
            
            #link_text_domain = gsub(link_text_domain, /\/[. \r\n\t]*/, "");
            link_text_domain = gsub(link_text_domain, /[ \r\n\t]+.*/, "");
            
            print_debug("3." + link_text_domain);
            
            local link_target_domain = sub(link_target, /^(http:\/\/|https:\/\/)/, "");
            # Scraps anything after the first / (if there is a first /)
            link_target_domain = gsub(link_target_domain, /\/.*/, "");
        
            # The difficulty is that the text isn't necessarily exclusively a URL - it can contain other data too.
            # So we're limited to how much cleaning we can safely do, without causing a false negative

            # Remove extra whitespace
            link_text_domain = strip(link_text_domain);
            link_target_domain = strip(link_target_domain);
    
            # Remove a trailing '.' from domains, in case someone includes a period in the link text.
            if (link_text_domain[-1] == "."){
                link_text_domain = link_text_domain[:-1];
            }
            if (link_target_domain[-1] == "."){
                link_target_domain = link_target_domain[:-1];
            }
            
            print_debug("URL Text Domain: " + link_text_domain);
            print_debug("URL Dest Domain: " + link_target_domain);

            local match_status = NA;
            if (link_text_domain == ""){
                #print "No domain in text";
                match_status = NA;
            }
            else{
                if (to_lower(link_text_domain) == to_lower(link_target_domain)){
                    print_debug("URL matches! Text and Dest: " + link_text_domain);
                    match_status = MATCH;
                }
                else{
                    print_debug("URL DOES NOT MATCH! Text: " + link_text_domain + " Dest: " + link_target_domain);
                    match_status = MISMATCH;
                }
            }

            result_links[|result_links|] = EmailLink($raw_data=link,
                                                     $text=link_text,
                                                     $target=link_target,
                                                     $text_domain=link_text_domain,
                                                     $target_domain=link_target_domain, 
                                                     $status=match_status);
        }
    }
    
    return result_links;
}

# Functions for generating notices
function log_mismatched_urls(links: LinkVector, conn: connection) : bool {

    local found_mismatch = F;
    
    for (i in links){
        if(links[i]$status == mismatched_links::MISMATCH){
            found_mismatch = T;
            local msg = fmt("Mismatched url! text=\"%s\" refers to target=\"%s\". Source input: %s",
                            links[i]$text,
                            links[i]$target,
                            links[i]$raw_data);
                            
            NOTICE([$note=LINK_TEXT_NOT_TARGET,
                    $msg=msg,
                    $sub=fmt("trans_depth=%s, target=%s", conn$smtp$trans_depth, links[i]$target),
                    $conn=conn
                    ]);            
        }
    }
    return found_mismatch;
}

# Event handlers

event mime_entity_data(conn: connection, length: count, data: string)
{
    local links = examine_links(data);
    log_mismatched_urls(links, conn);
} 

# Test cases:
function run_tests(){
    
    local valid_tests = vector(
        "foo<a href=\"http://example.com\" target=\"_blank\">http://example.com</a>bar",
        "foo<a href=\"http://gmail.com/\" target=\"_blank\" style=\"font-size:12.8px\">http://gmail.com</a>bar",
        "foo<a href=\"http://yahoo.com/\" target=\"_blank\" style=\"font-size:12.8px\">http://<span class=\"\">yahoo</span>.com</a>bar",
        "<a href=\"http://www.facebook.com/\" target=\"_top\">\nhttp://www.facebook.com</a>",
        "<a href=\"http://www.google.com/about\">\rhttp://www.google.com/about</a>"
    );
    
    local invalid_tests = vector(
        "foo<a href=\"https://www.gmail.com/\" target=\"_blank\">https://www.<span class=\"\">yahoo</span>.com/</a>bar",
        "foo<a href=\"https://www.gmail.com/\" target=\"_blank\">https://www.<div><span class=\"\">yahoo</san></div>.com/</a>bar",
        "foo<a href=\"http://foobar.com\" target=\"_blank\">http://foobar.com<address>my address</address></a>bar"
    );

    for (i in valid_tests){
        print fmt("Valid test #%d", i+1);
        print valid_tests[i];
        examine_links(valid_tests[i]);
        print "**************************";
    }
    
     for (i in invalid_tests){
        print fmt("Invalid test #%d", i+1);
        print invalid_tests[i];
        examine_links(invalid_tests[i]);
        print "**************************";
    }
    
}

event bro_init()
{
    if(DEBUG_MODE){
        run_tests();
    }
}
