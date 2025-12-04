
# utility functions
import logging
import os


def disable_proxy():
    for proxy_setting in [ 'http_proxy', 'https_proxy', 'ftp_proxy' ]:
        if proxy_setting in os.environ:
            logging.debug("removing proxy setting {}".format(proxy_setting))
            del os.environ[proxy_setting]

def recurse_analysis(analysis, level=0, current_tree=[], include_context=False):
    """Used to generate a textual display of the analysis results."""
    from saq.observables import FileObservable
    if not analysis:
        return

    if analysis in current_tree:
        return

    current_tree.append(analysis)

    if level > 0 and len(analysis.observables) == 0 and len(analysis.tags) == 0 and analysis.summary is None:
        return

    display = '{}{}{}'.format('\t' * level, 
                              '<' + '!' * len(analysis.detections) + '> ' if analysis.detections else '', 
                              analysis.summary if analysis.summary is not None else analysis.display_name)
    if analysis.tags:
        display += ' [ {} ] '.format(', '.join([x.name for x in analysis.tags]))
    
    print(display)

    if include_context:
        for context_document in analysis.llm_context_documents:
            print('\t' * level + f'🧠 {context_document}')

    for summary_detail in analysis.summary_details:
        print('{}{}'.format('\t' * level, summary_detail.content))

    for observable in analysis.observables:
        observable_value = observable.display_value

        display = '{} * {}{}:{}'.format('\t' * level, 
                                        '<' + '!' * len(observable.detections) + '> ' if observable.detections else '', 
                                         observable.display_type, 
                                         observable_value)
        if observable.time is not None:
            display += ' @ {0}'.format(observable.time)
        if observable.directives:
            display += ' {{ {} }} '.format(', '.join([x for x in observable.directives]))
        if observable.tags:
            display += ' [ {} ] '.format(', '.join([x.name for x in observable.tags]))
        if observable.volatile:
            display += ' <VOLATILE> '
        #if observable.pivot_links:
            #for pivot_link in observable.pivot_links:
                #display += f' 🔗 {pivot_link}'
        print(display)
        if include_context:
            for context_document in observable.llm_context_documents:
                print('\t' * level + f'🧠 {context_document}')

        for observable_analysis in observable.all_analysis:
            recurse_analysis(observable_analysis, level + 1, current_tree)

def display_analysis(root, include_context=False):
    recurse_analysis(root, include_context=include_context)

    tags = set(root.all_tags)
    if tags:
        print("{} TAGS".format(len(tags)))
        for tag in tags:
            print('* {}'.format(tag))

    detections = root.all_detection_points
    if detections:
        print("{} DETECTIONS FOUND (marked with <!> above)".format(len(detections)))
        for detection in detections:
            print('* {}'.format(detection))