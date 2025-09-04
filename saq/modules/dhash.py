import logging
import os
import os.path
from typing import Optional, override

from saq.analysis import Analysis
from saq.constants import F_FILE, DIRECTIVE_DHASH, G_ANALYST_DATA_DIR, AnalysisExecutionResult
from saq.environment import g
from saq.modules import AnalysisModule
from saq.modules.file_analysis import is_image
from saq.util.strings import format_item_list_for_summary

from PIL import Image
import dhash


dhash.force_pil()

IMAGE_SIZE = 16
PIXEL_SIZE = IMAGE_SIZE * IMAGE_SIZE * 2

KEY_SCORES = "scores"

class DHashImageAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            KEY_SCORES: [] 
        }

    @override
    @property
    def display_name(self) -> str:
        return "DHash Image Analysis"

    def add_score(self, image_file_path: str, score: float, threshold: float):
        self.details[KEY_SCORES].append({
            "image_file": image_file_path,
            "score": score,
            "threshold": threshold,
        })

    @property
    def scores(self) -> list[dict]:
        if not self.details:
            return []

        return self.details[KEY_SCORES]

    @override
    def generate_summary(self) -> Optional[str]:
        if not self.scores:
            return None

        summaries = []
        for score in self.scores:
            summaries.append(f"{score['image_file']} {score['score']:.2f}% of {score['threshold']:.2f}%")

        return f"{self.display_name}: " + format_item_list_for_summary(summaries)

class DHashImageAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return DHashImageAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_DHASH ]

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug("local file %s does not exist", local_file_path)
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug("local file %s is empty", local_file_path)
            return AnalysisExecutionResult.COMPLETED

        if not is_image(local_file_path):
            logging.debug("%s is not an image", local_file_path)
            return AnalysisExecutionResult.COMPLETED

        # the images we want to look for are stored in the analyst data repo
        source_dir = os.path.join(g(G_ANALYST_DATA_DIR), "dhash")
        if not os.path.isdir(source_dir):
            logging.warning("missing dhash source directory %s", source_dir)
            return AnalysisExecutionResult.COMPLETED

        target_image = Image.open(local_file_path)
        target_image_hash = dhash.dhash_int(target_image, size=IMAGE_SIZE)

        analysis = self.create_analysis(_file)

        for image_file_name in os.listdir(source_dir):
            if not image_file_name.endswith(".png"):
                continue

            source_image_file_path = os.path.join(source_dir, image_file_name)
            if not is_image(source_image_file_path):
                logging.debug("skipping non image file %s", source_image_file_path)
                continue

            score_threshold_path = f"{source_image_file_path}.score"
            try:
                with open(score_threshold_path, "r") as fp:
                    score_threshold = float(fp.read())
                    logging.debug("loaded score threshold %s for %s", score_threshold, score_threshold_path)
            except Exception as e:
                logging.error("unable to load score threshold from %s: %s", score_threshold_path, e)
                continue

            source_image = Image.open(source_image_file_path)
            source_image_hash = dhash.dhash_int(source_image, size=IMAGE_SIZE)
            bits_different = dhash.get_num_bits_different(source_image_hash, target_image_hash)
            percent_similar = 100.0 - ((bits_different / 512) * 100.0)
            logging.info("target %s source %s (%.2f) threshold (%.2f)",
                local_file_path,
                source_image_file_path,
                percent_similar,
                score_threshold)

            analysis.add_score(image_file_name, percent_similar, score_threshold)

            if percent_similar >= score_threshold:
                _file.add_detection_point(f"matches {image_file_name} {percent_similar:.2f}% (threshold {score_threshold:.2f}%)")

        return AnalysisExecutionResult.COMPLETED
